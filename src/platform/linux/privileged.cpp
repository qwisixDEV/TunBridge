#include "tunbridge/privileged.hpp"

#include "tunbridge/core.hpp"

#include <arpa/inet.h>
#include <dirent.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <functional>
#include <map>
#include <memory>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace tb {

struct PrivilegedStateImpl {
    struct Undo {
        std::function<bool(std::string*)> fn;
        std::string what;
    };
    std::vector<Undo> undo;
    int tunFd{-1};
    std::string tunName{"tunbridge0"};
    pid_t tun2socksPid{-1};
    std::vector<std::string> stoppedUnits;
    bool zapretUndo{false};
    bool dnsUndo{false};

    void push(std::function<bool(std::string*)> fn, std::string what) {
        undo.push_back(Undo{std::move(fn), std::move(what)});
    }
};

namespace {

constexpr std::size_t kMaxOutput = 1u << 20;
constexpr std::size_t kMaxFile = 16u << 20;

std::string sys_error(const char* what) {
    return std::string(what) + ": " + std::strerror(errno);
}

bool fail(std::string* err, std::string text) {
    if (err) *err = std::move(text);
    return false;
}

std::string env_or(const char* name, const char* fallback) {
    const char* value = std::getenv(name);
    return value && *value ? std::string(value) : std::string(fallback);
}

bool make_dirs(const std::string& path) {
    if (path.empty()) return false;
    std::string current;
    std::size_t i = 0;
    if (path.front() == '/') { current = "/"; i = 1; }
    while (i <= path.size()) {
        const std::size_t next = path.find('/', i);
        const std::string part = path.substr(i, next == std::string::npos ? std::string::npos : next - i);
        if (!part.empty()) {
            if (!current.empty() && current.back() != '/') current.push_back('/');
            current += part;
            if (::mkdir(current.c_str(), 0700) != 0 && errno != EEXIST) return false;
            struct stat st{};
            if (::stat(current.c_str(), &st) != 0 || !S_ISDIR(st.st_mode)) return false;
        }
        if (next == std::string::npos) break;
        i = next + 1;
    }
    return true;
}

bool write_all(int fd, const void* data, std::size_t len) {
    const char* p = static_cast<const char*>(data);
    std::size_t offset = 0;
    while (offset < len) {
        const ssize_t n = ::write(fd, p + offset, len - offset);
        if (n > 0) { offset += static_cast<std::size_t>(n); continue; }
        if (n < 0 && errno == EINTR) continue;
        return false;
    }
    return true;
}

bool read_file(const std::string& path, std::string* out, mode_t* mode = nullptr) {
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    struct stat st{};
    if (::fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        ::close(fd);
        return false;
    }
    if (mode) *mode = static_cast<mode_t>(st.st_mode & 07777);
    out->clear();
    std::array<char, 8192> buf{};
    for (;;) {
        const ssize_t n = ::read(fd, buf.data(), buf.size());
        if (n > 0) {
            if (out->size() + static_cast<std::size_t>(n) > kMaxFile) {
                ::close(fd);
                return false;
            }
            out->append(buf.data(), static_cast<std::size_t>(n));
            continue;
        }
        if (n < 0 && errno == EINTR) continue;
        ::close(fd);
        return n == 0;
    }
}

bool atomic_write(const std::string& path, const std::string& data, mode_t mode) {
    const std::size_t slash = path.find_last_of('/');
    const std::string dir = slash == std::string::npos ? std::string(".") : path.substr(0, slash);
    const std::string tmpl = dir + "/.tunbridge-tmp-XXXXXX";
    std::vector<char> name(tmpl.begin(), tmpl.end());
    name.push_back('\0');
    const int fd = ::mkstemp(name.data());
    if (fd < 0) return false;
    bool ok = write_all(fd, data.data(), data.size());
    if (ok && ::fchmod(fd, mode) != 0) ok = false;
    if (ok && ::fsync(fd) != 0) ok = false;
    ::close(fd);
    if (!ok) {
        ::unlink(name.data());
        return false;
    }
    if (::rename(name.data(), path.c_str()) != 0) {
        ::unlink(name.data());
        return false;
    }
    const int dirFd = ::open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dirFd >= 0) {
        (void)::fsync(dirFd);
        ::close(dirFd);
    }
    return true;
}

int remaining_ms(std::chrono::steady_clock::time_point deadline, int minMs, int maxMs) {
    const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(
                          deadline - std::chrono::steady_clock::now()).count();
    long long value = left < 0 ? 0 : left;
    if (value < minMs) value = minMs;
    if (value > maxMs) value = maxMs;
    return static_cast<int>(value);
}

// Bounded wait without spinning: poll() sleeps until the child exits.
bool wait_child(pid_t pid, int timeoutMs, int* statusOut) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
    for (;;) {
        int status = 0;
        const pid_t r = ::waitpid(pid, &status, WNOHANG);
        if (r == pid) {
            if (statusOut) *statusOut = status;
            return true;
        }
        if (r < 0) {
            if (errno == EINTR) continue;
            return errno == ECHILD;
        }
        if (std::chrono::steady_clock::now() >= deadline) {
            ::kill(pid, SIGTERM);
            ::poll(nullptr, 0, 150);
            if (::waitpid(pid, &status, WNOHANG) == 0) {
                ::kill(pid, SIGKILL);
                while (::waitpid(pid, &status, 0) < 0 && errno == EINTR) { /* retry */ }
            }
            return false;
        }
        ::poll(nullptr, 0, remaining_ms(deadline, 5, 50));
    }
}

// Executes argv directly (never through a shell). Output is captured only
// when requested; both cases have a hard timeout.
bool run_command(const std::vector<std::string>& args, std::string* out, int timeoutMs = 7000) {
    if (args.empty()) return false;
    int pfd[2] = {-1, -1};
    if (out && ::pipe2(pfd, O_CLOEXEC) != 0) return false;

    std::vector<char*> argv;
    argv.reserve(args.size() + 1);
    for (const auto& a : args) argv.push_back(const_cast<char*>(a.c_str()));
    argv.push_back(nullptr);

    const pid_t pid = ::fork();
    if (pid < 0) {
        if (out) { ::close(pfd[0]); ::close(pfd[1]); }
        return false;
    }
    if (pid == 0) {
        if (out) {
            ::close(pfd[0]);
            ::dup2(pfd[1], STDOUT_FILENO);
            ::close(pfd[1]);
        } else {
            const int nullFd = ::open("/dev/null", O_WRONLY);
            if (nullFd >= 0) {
                ::dup2(nullFd, STDOUT_FILENO);
                ::dup2(nullFd, STDERR_FILENO);
                if (nullFd > STDERR_FILENO) ::close(nullFd);
            }
        }
        ::execvp(argv[0], argv.data());
        ::_exit(127);
    }

    bool timedOut = false;
    if (out) {
        ::close(pfd[1]);
        const int flags = ::fcntl(pfd[0], F_GETFL, 0);
        if (flags >= 0) (void)::fcntl(pfd[0], F_SETFL, flags | O_NONBLOCK);
        out->clear();
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
        for (;;) {
            const int wait = remaining_ms(deadline, 1, 200);
            struct pollfd pfdIn{};
            pfdIn.fd = pfd[0];
            pfdIn.events = POLLIN;
            const int rc = ::poll(&pfdIn, 1, wait);
            if (rc < 0) {
                if (errno == EINTR) continue;
                break;
            }
            if (rc == 0) {
                if (std::chrono::steady_clock::now() >= deadline) timedOut = true;
                break;
            }
            std::array<char, 4096> buf{};
            const ssize_t n = ::read(pfd[0], buf.data(), buf.size());
            if (n > 0) {
                if (out->size() + static_cast<std::size_t>(n) <= kMaxOutput)
                    out->append(buf.data(), static_cast<std::size_t>(n));
                continue;
            }
            if (n == 0) break;
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
            break;
        }
        ::close(pfd[0]);
    }

    int status = 0;
    if (!wait_child(pid, timedOut ? 300 : timeoutMs, &status)) return false;
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

// Spawns a detached process, reporting exec() failures through a CLOEXEC pipe.
pid_t spawn_detached(const std::vector<std::string>& args, int* execErr) {
    int pfd[2] = {-1, -1};
    if (::pipe2(pfd, O_CLOEXEC) != 0) {
        if (execErr) *execErr = errno;
        return -1;
    }
    const pid_t pid = ::fork();
    if (pid < 0) {
        if (execErr) *execErr = errno;
        ::close(pfd[0]);
        ::close(pfd[1]);
        return -1;
    }
    if (pid == 0) {
        ::close(pfd[0]);
        (void)::setsid();
        const int nullFd = ::open("/dev/null", O_RDWR);
        if (nullFd >= 0) {
            ::dup2(nullFd, STDIN_FILENO);
            ::dup2(nullFd, STDOUT_FILENO);
            ::dup2(nullFd, STDERR_FILENO);
            if (nullFd > STDERR_FILENO) ::close(nullFd);
        }
        std::vector<char*> argv;
        argv.reserve(args.size() + 1);
        for (const auto& a : args) argv.push_back(const_cast<char*>(a.c_str()));
        argv.push_back(nullptr);
        ::execvp(argv[0], argv.data());
        const int e = errno;
        (void)::write(pfd[1], &e, sizeof(e));
        ::_exit(127);
    }
    ::close(pfd[1]);
    int childErr = 0;
    ssize_t n = 0;
    do {
        n = ::read(pfd[0], &childErr, sizeof(childErr));
    } while (n < 0 && errno == EINTR);
    ::close(pfd[0]);
    if (n > 0) {
        if (execErr) *execErr = childErr;
        int status = 0;
        (void)wait_child(pid, 1000, &status);
        return -1;
    }
    return pid;
}

void terminate_pid(pid_t pid) {
    if (pid <= 0) return;
    ::kill(pid, SIGTERM);
    ::poll(nullptr, 0, 200);
    if (::kill(pid, 0) == 0) ::kill(pid, SIGKILL);
    int status = 0;
    (void)wait_child(pid, 1000, &status);
}

struct GatewayInfo {
    bool found{false};
    std::string gateway;
    std::string iface;
    unsigned metric{0};
};

GatewayInfo read_default_gateway() {
    GatewayInfo best;
    std::ifstream file("/proc/net/route");
    std::string line;
    std::getline(file, line); // header
    while (std::getline(file, line)) {
        std::istringstream fields(line);
        std::string iface, dest, gate, flags, refcnt, use, metricText, mask;
        if (!(fields >> iface >> dest >> gate >> flags >> refcnt >> use >> metricText >> mask))
            continue;
        if (dest != "00000000" || mask != "00000000") continue;
        unsigned metric = 0;
        try { metric = static_cast<unsigned>(std::stoul(metricText, nullptr, 10)); }
        catch (...) { /* keep zero */ }
        if (best.found && metric >= best.metric) continue;
        unsigned long raw = 0;
        try { raw = std::stoul(gate, nullptr, 16); }
        catch (...) { continue; }
        struct in_addr addr{};
        addr.s_addr = static_cast<uint32_t>(raw); // /proc/net/route prints host-order hex
        char text[INET_ADDRSTRLEN]{};
        if (::inet_ntop(AF_INET, &addr, text, sizeof(text)) == nullptr) continue;
        best = GatewayInfo{true, text, iface, metric};
    }
    return best;
}

bool resolve_ipv4(const std::string& host, std::string& out) {
    if (host.empty()) return false;
    struct in_addr addr{};
    if (::inet_pton(AF_INET, host.c_str(), &addr) == 1) {
        out = host;
        return true;
    }
    struct addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo* result = nullptr;
    if (::getaddrinfo(host.c_str(), nullptr, &hints, &result) != 0 || result == nullptr) return false;
    char text[INET_ADDRSTRLEN]{};
    const auto* sa = reinterpret_cast<const struct sockaddr_in*>(result->ai_addr);
    const bool ok = ::inet_ntop(AF_INET, &sa->sin_addr, text, sizeof(text)) != nullptr;
    if (ok) out = text;
    ::freeaddrinfo(result);
    return ok;
}

bool create_tun(const std::string& name, int* fdOut, std::string* err) {
    const int fd = ::open("/dev/net/tun", O_RDWR | O_CLOEXEC);
    if (fd < 0) return fail(err, sys_error("open /dev/net/tun"));

    struct ifreq ifr{};
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    safe_copy(ifr.ifr_name, IFNAMSIZ, name.c_str());
    if (::ioctl(fd, TUNSETIFF, &ifr) < 0 && errno == EBUSY) {
        // Remove an interface left behind by an abruptly terminated helper.
        (void)run_command({"ip", "link", "del", name}, nullptr, 3000);
        std::memset(&ifr, 0, sizeof(ifr));
        ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
        safe_copy(ifr.ifr_name, IFNAMSIZ, name.c_str());
    }
    if (::ioctl(fd, TUNSETIFF, &ifr) < 0) {
        const std::string message = sys_error("ioctl TUNSETIFF");
        ::close(fd);
        return fail(err, message);
    }
    *fdOut = fd;
    return true;
}

bool configure_tun(const std::string& name, const std::string& address, std::string* err) {
    const int sock = ::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (sock < 0) return fail(err, sys_error("socket"));

    auto setAddress = [&](int request, const char* ip) {
        struct ifreq ifr{};
        safe_copy(ifr.ifr_name, IFNAMSIZ, name.c_str());
        ifr.ifr_addr.sa_family = AF_INET;
        (void)::inet_pton(AF_INET, ip, &reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_addr)->sin_addr);
        return ::ioctl(sock, request, &ifr) == 0;
    };

    bool ok = setAddress(SIOCSIFADDR, address.c_str());
    if (ok) ok = setAddress(SIOCSIFNETMASK, "255.255.255.0");
    if (ok) {
        struct ifreq ifr{};
        safe_copy(ifr.ifr_name, IFNAMSIZ, name.c_str());
        ifr.ifr_mtu = 1420;
        ok = ::ioctl(sock, SIOCSIFMTU, &ifr) == 0;
    }
    if (ok) {
        struct ifreq ifr{};
        safe_copy(ifr.ifr_name, IFNAMSIZ, name.c_str());
        ok = ::ioctl(sock, SIOCGIFFLAGS, &ifr) == 0;
        if (ok) {
            ifr.ifr_flags |= static_cast<short>(IFF_UP | IFF_RUNNING);
            ok = ::ioctl(sock, SIOCSIFFLAGS, &ifr) == 0;
        }
    }
    const std::string message = ok ? std::string() : sys_error("ioctl (TUN configure)");
    ::close(sock);
    return ok ? true : fail(err, message);
}

bool bring_tun_down(const std::string& name, std::string*) {
    const int sock = ::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (sock < 0) return false;
    struct ifreq ifr{};
    safe_copy(ifr.ifr_name, IFNAMSIZ, name.c_str());
    bool ok = ::ioctl(sock, SIOCGIFFLAGS, &ifr) == 0;
    if (ok) {
        ifr.ifr_flags &= static_cast<short>(~(IFF_UP | IFF_RUNNING));
        ok = ::ioctl(sock, SIOCSIFFLAGS, &ifr) == 0;
    }
    ::close(sock);
    return ok;
}

struct DnsBackup {
    bool hadFile{false};
    bool wasSymlink{false};
    std::string linkTarget;
    std::string targetPath;
    bool hadTarget{false};
    mode_t targetMode{0644};
    std::string targetContents;
    std::string contents;
    mode_t mode{0644};
};

std::string dns_meta_path() { return privileged_runtime_dir() + "/tunbridge-resolv-backup.meta"; }
std::string dns_data_path() { return privileged_runtime_dir() + "/tunbridge-resolv-backup.data"; }
std::string dns_target_path() { return privileged_runtime_dir() + "/tunbridge-resolv-target.data"; }
std::string zapret_state_path() { return privileged_runtime_dir() + "/tunbridge-zapret-stopped.txt"; }

bool backup_resolv_conf(DnsBackup& backup) {
    struct stat st{};
    if (::lstat("/etc/resolv.conf", &st) != 0) {
        if (errno == ENOENT) { backup.hadFile = false; return true; }
        return false;
    }
    backup.hadFile = true;
    if (S_ISLNK(st.st_mode)) {
        backup.wasSymlink = true;
        std::array<char, 4096> buf{};
        const ssize_t n = ::readlink("/etc/resolv.conf", buf.data(), buf.size() - 1);
        if (n < 0) return false;
        backup.linkTarget.assign(buf.data(), static_cast<std::size_t>(n));
        backup.targetPath = !backup.linkTarget.empty() && backup.linkTarget.front() == '/'
                                ? backup.linkTarget
                                : std::string("/etc/") + backup.linkTarget;
        struct stat targetStat{};
        if (::stat(backup.targetPath.c_str(), &targetStat) == 0 && S_ISREG(targetStat.st_mode)) {
            backup.hadTarget = true;
            backup.targetMode = static_cast<mode_t>(targetStat.st_mode & 07777);
            if (!read_file(backup.targetPath, &backup.targetContents)) backup.hadTarget = false;
        }
        return true;
    }
    if (S_ISREG(st.st_mode)) {
        backup.mode = static_cast<mode_t>(st.st_mode & 07777);
        return read_file("/etc/resolv.conf", &backup.contents, nullptr);
    }
    return false;
}

bool restore_resolv_conf(const DnsBackup& backup) {
    if (backup.wasSymlink) {
        ::unlink("/etc/resolv.conf");
        if (backup.hadTarget && !atomic_write(backup.targetPath, backup.targetContents, backup.targetMode))
            return false;
        return ::symlink(backup.linkTarget.c_str(), "/etc/resolv.conf") == 0;
    }
    if (backup.hadFile) return atomic_write("/etc/resolv.conf", backup.contents, backup.mode);
    if (::unlink("/etc/resolv.conf") == 0 || errno == ENOENT) return true;
    return false;
}

void clear_dns_backup_files() {
    ::unlink(dns_meta_path().c_str());
    ::unlink(dns_data_path().c_str());
    ::unlink(dns_target_path().c_str());
}

bool persist_dns_backup(const DnsBackup& backup) {
    if (!make_dirs(privileged_runtime_dir())) return false;
    std::ostringstream meta;
    meta << "hadFile=" << (backup.hadFile ? 1 : 0) << '\n'
         << "wasSymlink=" << (backup.wasSymlink ? 1 : 0) << '\n'
         << "linkTarget=" << backup.linkTarget << '\n'
         << "targetPath=" << backup.targetPath << '\n'
         << "hadTarget=" << (backup.hadTarget ? 1 : 0) << '\n'
         << "mode=" << static_cast<unsigned>(backup.mode) << '\n'
         << "targetMode=" << static_cast<unsigned>(backup.targetMode) << '\n';
    if (!atomic_write(dns_meta_path(), meta.str(), 0600)) return false;
    if (backup.hadFile && !atomic_write(dns_data_path(), backup.contents, 0600)) return false;
    if (backup.hadTarget && !atomic_write(dns_target_path(), backup.targetContents, 0600)) return false;
    return true;
}

bool load_persistent_dns_backup(DnsBackup& backup) {
    std::string meta;
    if (!read_file(dns_meta_path(), &meta)) return false;
    std::map<std::string, std::string> values;
    std::istringstream lines(meta);
    std::string line;
    while (std::getline(lines, line)) {
        const std::size_t eq = line.find('=');
        if (eq == std::string::npos || eq == 0) continue;
        values[line.substr(0, eq)] = line.substr(eq + 1);
    }
    const auto number = [&](const char* key, unsigned fallback) {
        const auto it = values.find(key);
        if (it == values.end()) return fallback;
        try { return static_cast<unsigned>(std::stoul(it->second, nullptr, 10)); }
        catch (...) { return fallback; }
    };
    backup = DnsBackup{};
    backup.hadFile = number("hadFile", 0) != 0;
    backup.wasSymlink = number("wasSymlink", 0) != 0;
    backup.hadTarget = number("hadTarget", 0) != 0;
    backup.mode = static_cast<mode_t>(number("mode", 0644));
    backup.targetMode = static_cast<mode_t>(number("targetMode", 0644));
    backup.linkTarget = values.count("linkTarget") ? values["linkTarget"] : std::string();
    backup.targetPath = values.count("targetPath") ? values["targetPath"] : std::string();
    if (backup.hadFile && !read_file(dns_data_path(), &backup.contents)) return false;
    if (backup.hadTarget && !read_file(dns_target_path(), &backup.targetContents)) return false;
    return true;
}

bool resolved_active() {
    if (::access("/run/systemd/resolve/stub-resolv.conf", F_OK) == 0) return true;
    return run_command({"systemctl", "is-active", "--quiet", "systemd-resolved"}, nullptr, 3000);
}

std::vector<std::string> split_ws(const std::string& text) {
    std::vector<std::string> out;
    std::istringstream in(text);
    std::string token;
    while (in >> token) out.push_back(token);
    return out;
}

bool safe_dns_server(const std::string& server) {
    if (server.empty() || server.size() > 128) return false;
    for (const char ch : server) {
        const unsigned char c = static_cast<unsigned char>(ch);
        const bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') ||
                        (c >= 'A' && c <= 'Z') || c == '.' || c == ':' || c == '-';
        if (!ok) return false;
    }
    return true;
}

bool setup_dns(PrivilegedStateImpl& state, const HelperRequest& req, std::string* err) {
    std::vector<std::string> servers = split_ws(req.dnsServers);
    if (servers.empty()) servers = {"1.1.1.1", "8.8.8.8"};
    for (const auto& s : servers) {
        if (!safe_dns_server(s)) return fail(err, "Некорректный адрес DNS-сервера: " + s);
    }

    if (resolved_active()) {
        std::vector<std::string> dnsArgs{"resolvectl", "dns", state.tunName};
        dnsArgs.insert(dnsArgs.end(), servers.begin(), servers.end());
        if (!run_command(dnsArgs, nullptr)) return fail(err, "Не удалось задать DNS через resolvectl");
        if (!run_command({"resolvectl", "domain", state.tunName, "~."}, nullptr))
            return fail(err, "Не удалось задать DNS-домен через resolvectl");
        (void)run_command({"resolvectl", "flush-caches"}, nullptr, 3000);
        const std::string ifName = state.tunName;
        state.push([ifName](std::string*) {
            return run_command({"resolvectl", "revert", ifName}, nullptr, 5000);
        }, "сброс DNS через resolvectl");
        return true;
    }

    DnsBackup backup;
    if (!backup_resolv_conf(backup)) return fail(err, "Не удалось сохранить /etc/resolv.conf");
    std::string content;
    for (const auto& s : servers) content += "nameserver " + s + "\n";
    content += "options timeout:2 attempts:2\n";
    if (!atomic_write("/etc/resolv.conf", content, 0644))
        return fail(err, "Не удалось записать /etc/resolv.conf");
    if (!persist_dns_backup(backup)) {
        (void)restore_resolv_conf(backup);
        return fail(err, "Не удалось сохранить резервную копию /etc/resolv.conf");
    }
    state.push([backup](std::string* e) {
        const bool ok = restore_resolv_conf(backup);
        clear_dns_backup_files();
        if (!ok && e) *e = "Не удалось восстановить /etc/resolv.conf";
        return ok;
    }, "восстановление /etc/resolv.conf");
    return true;
}

std::vector<std::string> active_zapret_units() {
    std::string output;
    (void)run_command({"systemctl", "list-units", "--type=service", "--state=active",
                       "--no-legend", "--plain"},
                      &output, 5000);
    std::vector<std::string> units;
    std::istringstream lines(output);
    std::string line;
    while (std::getline(lines, line)) {
        std::istringstream fields(line);
        std::string unit;
        if (!(fields >> unit) || unit.empty()) continue;
        std::string lower;
        lower.reserve(unit.size());
        for (const char ch : unit)
            lower.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
        if (lower.rfind("zapret", 0) == 0) units.push_back(unit);
    }
    if (units.empty()) {
        std::string state;
        if (run_command({"systemctl", "is-active", "zapret"}, &state, 3000)) {
            while (!state.empty() && (state.back() == '\n' || state.back() == '\r')) state.pop_back();
            if (state == "active") units.push_back("zapret.service");
        }
    }
    return units;
}

std::vector<pid_t> processes_named(const std::vector<std::string>& names) {
    std::vector<pid_t> pids;
    DIR* dir = ::opendir("/proc");
    if (dir == nullptr) return pids;
    while (struct dirent* entry = ::readdir(dir)) {
        if (entry->d_name[0] < '0' || entry->d_name[0] > '9') continue;
        std::string comm;
        if (!read_file(std::string("/proc/") + entry->d_name + "/comm", &comm)) continue;
        while (!comm.empty() && (comm.back() == '\n' || comm.back() == '\r')) comm.pop_back();
        if (std::find(names.begin(), names.end(), comm) == names.end()) continue;
        try { pids.push_back(static_cast<pid_t>(std::stol(entry->d_name))); }
        catch (...) { /* skip */ }
    }
    ::closedir(dir);
    return pids;
}

void stop_zapret_processes() {
    const std::vector<pid_t> pids = processes_named({"nfqws", "tpws"});
    if (pids.empty()) return;
    for (const pid_t pid : pids) {
        if (pid > 0 && pid != ::getpid()) (void)::kill(pid, SIGTERM);
    }
    ::poll(nullptr, 0, 200);
    for (const pid_t pid : pids) {
        if (pid > 0 && pid != ::getpid() && ::kill(pid, 0) == 0) (void)::kill(pid, SIGKILL);
    }
}

bool persist_stopped_units(const std::vector<std::string>& units) {
    if (units.empty()) {
        ::unlink(zapret_state_path().c_str());
        return true;
    }
    if (!make_dirs(privileged_runtime_dir())) return false;
    std::string text;
    for (const auto& unit : units) text += unit + "\n";
    return atomic_write(zapret_state_path(), text, 0600);
}

std::vector<std::string> load_stopped_units() {
    std::vector<std::string> units;
    std::string text;
    if (!read_file(zapret_state_path(), &text)) return units;
    std::istringstream lines(text);
    std::string unit;
    while (std::getline(lines, unit)) {
        while (!unit.empty() && (unit.back() == '\n' || unit.back() == '\r')) unit.pop_back();
        if (!unit.empty()) units.push_back(unit);
    }
    return units;
}

bool start_units(const std::vector<std::string>& units, std::string* err) {
    bool ok = true;
    for (const auto& unit : units) {
        if (!run_command({"systemctl", "start", unit}, nullptr, 6000)) {
            ok = false;
            if (err) {
                if (!err->empty()) err->push_back(';');
                err->append("не удалось запустить ").append(unit);
            }
        }
    }
    return ok;
}

bool stop_zapret_impl(PrivilegedStateImpl& state, std::string* err) {
    const std::vector<std::string> units = active_zapret_units();
    std::vector<std::string> stopped;
    bool ok = true;
    for (const auto& unit : units) {
        if (run_command({"systemctl", "stop", unit}, nullptr, 6000)) {
            if (std::find(stopped.begin(), stopped.end(), unit) == stopped.end())
                stopped.push_back(unit);
        } else {
            ok = false;
        }
    }
    stop_zapret_processes();
    if (!stopped.empty()) {
        for (const auto& unit : stopped) {
            if (std::find(state.stoppedUnits.begin(), state.stoppedUnits.end(), unit) ==
                state.stoppedUnits.end())
                state.stoppedUnits.push_back(unit);
        }
        (void)persist_stopped_units(state.stoppedUnits);
        if (!state.zapretUndo) {
            state.zapretUndo = true;
            state.push([stopped](std::string* e) {
                const bool restored = start_units(stopped, e);
                (void)persist_stopped_units({});
                return restored;
            }, "возобновление служб Zapret");
        }
    }
    if (ok && err) *err = stopped.empty() ? "Активные службы Zapret не найдены"
                                          : "Службы Zapret остановлены";
    if (!ok && err) *err = "Не удалось остановить все службы Zapret";
    return ok;
}

} // namespace

bool privileged_is_root() {
    return ::geteuid() == 0;
}

namespace {
std::string g_runtimeOverride;
} // namespace

std::string privileged_runtime_dir() {
    if (!g_runtimeOverride.empty()) return g_runtimeOverride;
    const char* env = std::getenv("XDG_RUNTIME_DIR");
    if (env && *env) return env;
    char buf[80];
    std::snprintf(buf, sizeof(buf), "/run/user/%u", static_cast<unsigned>(::getuid()));
    return buf;
}

bool set_privileged_runtime_dir(const std::string& path) {
    if (path.empty()) return true;
    if (path.front() != '/' || path.find('\n') != std::string::npos ||
        path.find('\r') != std::string::npos)
        return false;
    g_runtimeOverride = path;
    while (g_runtimeOverride.size() > 1 && g_runtimeOverride.back() == '/')
        g_runtimeOverride.pop_back();
    return true;
}

PrivilegedState::PrivilegedState() : impl_(std::make_unique<PrivilegedStateImpl>()) {}

PrivilegedState::~PrivilegedState() {
    rollback();
}

void PrivilegedState::rollback() {
    if (!impl_) return;
    std::vector<PrivilegedStateImpl::Undo> actions;
    actions.swap(impl_->undo);
    for (auto it = actions.rbegin(); it != actions.rend(); ++it) {
        std::string ignored;
        try {
            if (it->fn) (void)it->fn(&ignored);
        } catch (...) {
            // One failed step must not prevent the remaining rollback steps.
        }
    }
    if (impl_->tunFd >= 0) {
        ::close(impl_->tunFd);
        impl_->tunFd = -1;
    }
    impl_->tun2socksPid = -1;
    impl_->zapretUndo = false;
    impl_->dnsUndo = false;
    impl_->stoppedUnits.clear();
}

void PrivilegedState::commit() {
    if (!impl_) return;
    impl_->undo.clear();
    if (impl_->tunFd >= 0) {
        ::close(impl_->tunFd);
        impl_->tunFd = -1;
    }
    impl_->tun2socksPid = -1;
    impl_->zapretUndo = false;
    impl_->dnsUndo = false;
}

bool PrivilegedState::has_changes() const {
    return impl_ && (!impl_->undo.empty() || impl_->tunFd >= 0);
}

bool PrivilegedState::start_tun(const HelperRequest& req, std::string* err) {
    rollback();
    if (!privileged_is_root()) return fail(err, "Для настройки TUN требуются права root");
    PrivilegedStateImpl& state = *impl_;
    state.tunName = req.tunInterface.empty() ? "tunbridge0" : req.tunInterface;
    if (state.tunName.empty() || state.tunName.size() >= IFNAMSIZ ||
        state.tunName.find('/') != std::string::npos)
        return fail(err, "Некорректное имя TUN-интерфейса");
    const std::string address = req.tunAddress.empty() ? "10.251.251.1" : req.tunAddress;
    const std::string peer = req.tunPeer.empty() ? "10.251.251.2" : req.tunPeer;

    std::string detail;
    int fd = -1;
    if (!create_tun(state.tunName, &fd, &detail)) {
        rollback();
        return fail(err, "Не удалось создать TUN-интерфейс: " + detail);
    }
    state.tunFd = fd;
    const int ownedFd = fd;
    state.push([ownedFd](std::string*) {
        ::close(ownedFd);
        return true;
    }, "удаление TUN-интерфейса");

    if (!configure_tun(state.tunName, address, &detail)) {
        rollback();
        return fail(err, "Не удалось настроить TUN-интерфейс: " + detail);
    }
    const std::string tunForDown = state.tunName;
    state.push([tunForDown](std::string*) {
        return bring_tun_down(tunForDown, nullptr);
    }, "отключение TUN-интерфейса");

    auto add_route = [&](std::vector<std::string> add, std::vector<std::string> remove,
                         std::string description) {
        if (!run_command(add, nullptr, 6000)) {
            detail = "не удалось добавить маршрут: " + add.back();
            return false;
        }
        state.push([remove](std::string*) {
            return run_command(remove, nullptr, 6000);
        }, std::move(description));
        return true;
    };

    std::string proxyIp;
    if (!resolve_ipv4(req.net.ip, proxyIp)) {
        rollback();
        return fail(err, "Не удалось определить IP-адрес прокси: " + std::string(req.net.ip));
    }
    const GatewayInfo gateway = read_default_gateway();
    if (gateway.found) {
        const std::vector<std::string> add{"ip", "route", "replace", proxyIp + "/32",
                                           "via", gateway.gateway, "dev", gateway.iface,
                                           "metric", "1"};
        const std::vector<std::string> remove{"ip", "route", "del", proxyIp + "/32",
                                              "via", gateway.gateway, "dev", gateway.iface,
                                              "metric", "1"};
        if (!add_route(add, remove, "удаление маршрута к прокси")) {
            rollback();
            return fail(err, detail);
        }
    }
    for (const char* network : {"0.0.0.0/1", "128.0.0.0/1"}) {
        const std::vector<std::string> add{"ip", "route", "add", network,
                                           "via", peer, "dev", state.tunName, "metric", "1"};
        const std::vector<std::string> remove{"ip", "route", "del", network,
                                              "via", peer, "dev", state.tunName, "metric", "1"};
        if (!add_route(add, remove, "удаление маршрута " + std::string(network))) {
            rollback();
            return fail(err, detail);
        }
    }

    // IPv6 leak prevention. A blackhole route is preferred; the policy rule is
    // a fallback for kernels where that route cannot be installed.
    bool ipv6Blocked = run_command({"ip", "-6", "route", "add", "blackhole", "::/0",
                                    "dev", "lo"}, nullptr, 5000);
    if (ipv6Blocked) {
        state.push([] (std::string*) {
            return run_command({"ip", "-6", "route", "del", "blackhole", "::/0",
                                "dev", "lo"}, nullptr, 5000);
        }, "удаление чёрного IPv6-маршрута");
    } else {
        ipv6Blocked = run_command({"ip", "-6", "rule", "add", "unreachable"}, nullptr, 5000);
        if (ipv6Blocked) {
            state.push([] (std::string*) {
                return run_command({"ip", "-6", "rule", "del", "unreachable"}, nullptr, 5000);
            }, "удаление IPv6-правила");
        }
    }
    // If IPv6 is disabled in the kernel neither command can succeed; this is
    // not an error because there is no leak in that case.

    if (!setup_dns(state, req, &detail)) {
        rollback();
        return fail(err, detail);
    }
    if (req.stopZapret) {
        if (!stop_zapret_impl(state, &detail)) {
            rollback();
            return fail(err, detail);
        }
    }

    const std::string dataHome = req.dataDir.empty()
                                     ? env_or("XDG_DATA_HOME", "")
                                     : req.dataDir;
    if (!req.dataDir.empty() && (req.dataDir.front() != '/' ||
                                 req.dataDir.find('\n') != std::string::npos ||
                                 req.dataDir.find('\r') != std::string::npos)) {
        rollback();
        return fail(err, "Некорректный каталог данных tun2socks");
    }
    const std::string binary = (dataHome.empty()
                                    ? env_or("HOME", "/root") + "/.local/share"
                                    : dataHome) +
                               "/tunbridge/bin/tun2socks";
    struct stat binaryStat{};
    // Refuse symlinks and world/group-writable binaries: the helper runs as
    // root and must not execute a file another local user can replace.
    if (::lstat(binary.c_str(), &binaryStat) != 0 || !S_ISREG(binaryStat.st_mode) ||
        (binaryStat.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        rollback();
        return fail(err, "Не найден безопасный исполняемый файл tun2socks: " + binary);
    }
    const std::vector<std::string> tunArgs{
        binary, "--device", "tun://" + state.tunName,
        "--proxy", proxy_url(req.net, req.proto), "--loglevel", "error"};
    int execErr = 0;
    const pid_t pid = spawn_detached(tunArgs, &execErr);
    if (pid < 0) {
        rollback();
        return fail(err, std::string("Не удалось запустить tun2socks: ") + std::strerror(execErr));
    }
    state.tun2socksPid = pid;
    state.push([pid](std::string*) {
        terminate_pid(pid);
        return true;
    }, "остановка tun2socks");

    if (err) *err = "TUN-режим запущен: " + state.tunName +
                    (gateway.found ? " (прокси через " + gateway.gateway + ")" : "");
    return true;
}

bool PrivilegedState::stop_tun(std::string* err) {
    if (has_changes()) {
        rollback();
        commit();
        if (err) *err = "TUN-режим остановлен";
        return true;
    }

    // A fresh helper process has no in-memory state: perform an idempotent
    // best-effort cleanup instead of rolling back somebody else's changes.
    for (const pid_t pid : processes_named({"tun2socks"})) {
        if (pid > 0 && pid != ::getpid()) (void)::kill(pid, SIGTERM);
    }
    ::poll(nullptr, 0, 200);
    for (const pid_t pid : processes_named({"tun2socks"})) {
        if (pid > 0 && pid != ::getpid() && ::kill(pid, 0) == 0) (void)::kill(pid, SIGKILL);
    }
    (void)run_command({"resolvectl", "revert", "tunbridge0"}, nullptr, 5000);
    (void)run_command({"ip", "route", "del", "0.0.0.0/1"}, nullptr, 5000);
    (void)run_command({"ip", "route", "del", "128.0.0.0/1"}, nullptr, 5000);
    (void)run_command({"ip", "-6", "route", "del", "blackhole", "::/0", "dev", "lo"}, nullptr, 5000);
    (void)run_command({"ip", "-6", "rule", "del", "unreachable"}, nullptr, 5000);
    (void)run_command({"ip", "link", "del", "tunbridge0"}, nullptr, 5000);
    DnsBackup backup;
    if (load_persistent_dns_backup(backup)) {
        (void)restore_resolv_conf(backup);
        clear_dns_backup_files();
    }
    commit();
    if (err) *err = "TUN-режим остановлен";
    return true;
}

bool PrivilegedState::stop_zapret(std::string* err) {
    return stop_zapret_impl(*impl_, err);
}

bool PrivilegedState::restore_zapret(std::string* err) {
    std::vector<std::string> units = impl_->stoppedUnits;
    for (const auto& unit : load_stopped_units()) {
        if (std::find(units.begin(), units.end(), unit) == units.end()) units.push_back(unit);
    }
    if (units.empty()) {
        if (err) *err = "Нет остановленных служб Zapret";
        return true;
    }
    std::string detail;
    const bool ok = start_units(units, &detail);
    if (ok) {
        impl_->stoppedUnits.clear();
        (void)persist_stopped_units({});
        if (err) *err = "Службы Zapret возобновлены";
        return true;
    }
    impl_->stoppedUnits = units;
    (void)persist_stopped_units(units);
    return fail(err, detail);
}

bool PrivilegedState::zapret_active(std::string* detail) const {
    const std::vector<std::string> units = active_zapret_units();
    const std::vector<pid_t> processes = processes_named({"nfqws", "tpws"});
    if (detail) {
        std::ostringstream out;
        if (!units.empty()) {
            out << "systemd: ";
            for (std::size_t i = 0; i < units.size(); ++i) {
                if (i) out << ", ";
                out << units[i];
            }
        }
        if (!processes.empty()) {
            if (!units.empty()) out << "; ";
            out << "процессы: ";
            for (std::size_t i = 0; i < processes.size(); ++i) {
                if (i) out << ", ";
                out << static_cast<long long>(processes[i]);
            }
        }
        if (units.empty() && processes.empty()) out << "Zapret не активен";
        *detail = out.str();
    }
    return !units.empty() || !processes.empty();
}

} // namespace tb

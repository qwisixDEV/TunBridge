#include "tunbridge/helper_protocol.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <string_view>
#include <utility>
#include <vector>

#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

namespace tb {
namespace {

constexpr std::size_t kMaxText = 1u << 20; // 1 MiB is plenty for a request.

std::string sys_error(const char* what) {
    return std::string(what) + ": " + std::strerror(errno);
}

bool fail(std::string* err, std::string text) {
    if (err) *err = std::move(text);
    return false;
}

void append_escaped(std::string& out, std::string_view value) {
    for (const char ch : value) {
        switch (ch) {
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:   out.push_back(ch); break;
        }
    }
}

bool unescape(std::string_view value, std::string& out) {
    out.clear();
    out.reserve(value.size());
    for (std::size_t i = 0; i < value.size(); ++i) {
        if (value[i] != '\\') {
            out.push_back(value[i]);
            continue;
        }
        if (++i >= value.size()) return false;
        switch (value[i]) {
            case '\\': out.push_back('\\'); break;
            case 'n':  out.push_back('\n'); break;
            case 'r':  out.push_back('\r'); break;
            case 't':  out.push_back('\t'); break;
            default: return false;
        }
    }
    return true;
}

void add_line(std::string& out, std::string_view key, std::string_view value) {
    out.append(key);
    out.push_back('=');
    append_escaped(out, value);
    out.push_back('\n');
}

bool parse_fields(const std::string& text, std::map<std::string, std::string>& out) {
    if (text.size() > kMaxText) return false;
    out.clear();
    std::size_t pos = 0;
    bool terminated = false;
    while (pos < text.size()) {
        const std::size_t end = text.find('\n', pos);
        const bool hasNewline = end != std::string::npos;
        std::string_view line(text.data() + pos, (hasNewline ? end : text.size()) - pos);
        pos = hasNewline ? end + 1 : text.size();
        if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
        if (line.empty()) {
            terminated = true;
            break;
        }
        const std::size_t eq = line.find('=');
        if (eq == std::string_view::npos || eq == 0) return false;
        std::string value;
        if (!unescape(line.substr(eq + 1), value)) return false;
        out.emplace(std::string(line.substr(0, eq)), std::move(value));
    }
    return terminated && !out.empty();
}

template <typename T>
bool parse_number(const std::string& s, T& out) {
    T value{};
    const char* begin = s.data();
    const char* end = begin + s.size();
    const auto result = std::from_chars(begin, end, value);
    if (result.ec != std::errc{} || result.ptr != end) return false;
    out = value;
    return true;
}

bool parse_bool(const std::string& s, bool& out) {
    if (s == "0" || s == "false") { out = false; return true; }
    if (s == "1" || s == "true")  { out = true;  return true; }
    return false;
}

const std::string* field(const std::map<std::string, std::string>& f, const char* key) {
    const auto it = f.find(key);
    return it == f.end() ? nullptr : &it->second;
}

std::string runtime_dir() {
    const char* env = std::getenv("XDG_RUNTIME_DIR");
    if (env && *env) return env;
    char buf[80];
    std::snprintf(buf, sizeof(buf), "/run/user/%u", static_cast<unsigned>(getuid()));
    return buf;
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

int remaining_ms(std::chrono::steady_clock::time_point deadline) {
    const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(
                          deadline - std::chrono::steady_clock::now()).count();
    if (left <= 0) return 0;
    if (left > 1000) return 1000;
    return static_cast<int>(left);
}

bool send_all(int fd, std::string_view data, std::string* err) {
    std::size_t offset = 0;
    while (offset < data.size()) {
        const ssize_t n = ::send(fd, data.data() + offset, data.size() - offset, MSG_NOSIGNAL);
        if (n > 0) { offset += static_cast<std::size_t>(n); continue; }
        if (n < 0 && errno == EINTR) continue;
        if (n == 0) return fail(err, "Помощник закрыл канал при отправке запроса");
        return fail(err, sys_error("send"));
    }
    return true;
}

// Reads exactly one key=value frame terminated by an empty line.
bool read_frame(int fd, std::string& text, std::string* err) {
    text.clear();
    std::string buffer;
    std::array<char, 4096> chunk{};
    while (buffer.size() < kMaxText) {
        const ssize_t n = ::recv(fd, chunk.data(), chunk.size(), 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            return fail(err, sys_error("recv"));
        }
        if (n == 0) return fail(err, "Помощник закрыл соединение до конца ответа");
        buffer.append(chunk.data(), static_cast<std::size_t>(n));
        const std::size_t end = buffer.find("\n\n");
        if (end != std::string::npos) {
            // Keep both newlines: parse_fields() uses the empty line as the
            // explicit end-of-frame marker.
            text.assign(buffer, 0, end + 2);
            return true;
        }
    }
    return fail(err, "Слишком большой ответ помощника");
}

void reap_helper(pid_t pid) {
    if (pid <= 0) return;
    int status = 0;
    pid_t r = ::waitpid(pid, &status, WNOHANG);
    if (r == pid || (r < 0 && errno == ECHILD)) return;
    if (r == 0) {
        ::kill(pid, SIGTERM);
        ::poll(nullptr, 0, 150);
        r = ::waitpid(pid, &status, WNOHANG);
        if (r == 0) {
            ::kill(pid, SIGKILL);
            while (::waitpid(pid, &status, 0) < 0 && errno == EINTR) { /* retry */ }
        }
    }
}

} // namespace

std::string encode_request(const HelperRequest& r) {
    std::string out;
    out.reserve(512);
    add_line(out, "action", std::to_string(static_cast<int>(r.action)));
    add_line(out, "ip", r.net.ip);
    add_line(out, "sport", std::to_string(r.net.socksPort));
    add_line(out, "user", r.net.user);
    add_line(out, "pass", r.net.pass);
    add_line(out, "lport", std::to_string(r.net.localPort));
    add_line(out, "proto", std::to_string(static_cast<int>(r.proto)));
    add_line(out, "tunInterface", r.tunInterface);
    add_line(out, "tunAddress", r.tunAddress);
    add_line(out, "tunPeer", r.tunPeer);
    add_line(out, "dnsServers", r.dnsServers);
    add_line(out, "dataDir", r.dataDir);
    add_line(out, "runtimeDir", r.runtimeDir);
    add_line(out, "stopZapret", r.stopZapret ? "1" : "0");
    add_line(out, "restoreZapret", r.restoreZapret ? "1" : "0");
    out.push_back('\n');
    return out;
}

bool decode_request(const std::string& text, HelperRequest& r) {
    std::map<std::string, std::string> f;
    if (!parse_fields(text, f)) return false;

    HelperRequest out;
    if (const std::string* p = field(f, "action")) {
        int v = 0;
        if (!parse_number(*p, v) || v < 0 || v > 4) return false;
        out.action = static_cast<HelperAction>(v);
    }
    if (const std::string* p = field(f, "ip")) safe_copy(out.net.ip, sizeof(out.net.ip), p->c_str());
    if (const std::string* p = field(f, "sport")) {
        int v = 0;
        if (!parse_number(*p, v) || v < 1 || v > 65535) return false;
        out.net.socksPort = v;
    }
    if (const std::string* p = field(f, "user")) safe_copy(out.net.user, sizeof(out.net.user), p->c_str());
    if (const std::string* p = field(f, "pass")) safe_copy(out.net.pass, sizeof(out.net.pass), p->c_str());
    if (const std::string* p = field(f, "lport")) {
        int v = 0;
        if (!parse_number(*p, v) || v < 1 || v > 65535) return false;
        out.net.localPort = v;
    }
    if (const std::string* p = field(f, "proto")) {
        int v = 0;
        if (!parse_number(*p, v) || v < 0 || v > 2) return false;
        out.proto = static_cast<UpstreamProto>(v);
    }
    if (const std::string* p = field(f, "tunInterface")) out.tunInterface = *p;
    if (const std::string* p = field(f, "tunAddress")) out.tunAddress = *p;
    if (const std::string* p = field(f, "tunPeer")) out.tunPeer = *p;
    if (const std::string* p = field(f, "dnsServers")) out.dnsServers = *p;
    if (const std::string* p = field(f, "dataDir")) out.dataDir = *p;
    if (const std::string* p = field(f, "runtimeDir")) out.runtimeDir = *p;
    if (const std::string* p = field(f, "stopZapret")) {
        if (!parse_bool(*p, out.stopZapret)) return false;
    }
    if (const std::string* p = field(f, "restoreZapret")) {
        if (!parse_bool(*p, out.restoreZapret)) return false;
    }
    r = std::move(out);
    return true;
}

std::string encode_reply(const HelperReply& r) {
    std::string out;
    add_line(out, "ok", r.ok ? "1" : "0");
    add_line(out, "message", r.message);
    out.push_back('\n');
    return out;
}

bool decode_reply(const std::string& text, HelperReply& r) {
    std::map<std::string, std::string> f;
    if (!parse_fields(text, f)) return false;
    HelperReply out;
    if (const std::string* p = field(f, "ok")) {
        if (!parse_bool(*p, out.ok)) return false;
    } else {
        return false;
    }
    if (const std::string* p = field(f, "message")) out.message = *p;
    r = std::move(out);
    return true;
}

HelperClient::~HelperClient() {
    disconnect();
    reap_helper(helperPid_);
    helperPid_ = -1;
    if (!socketPath_.empty()) {
        ::unlink(socketPath_.c_str());
        socketPath_.clear();
    }
}

HelperReply HelperClient::launch(const HelperRequest& r, const std::string& helperPath,
                                 std::string* err, int timeoutMs) {
    HelperReply reply;
    reply.message = "Помощник не запущен";
    if (err) err->clear();
    const auto report = [&](std::string text) {
        if (err) *err = text;
        reply.message = std::move(text);
    };
    disconnect();
    if (helperPid_ > 0) {
        reap_helper(helperPid_);
        helperPid_ = -1;
    }

    if (helperPath.empty()) return reply;
    if (!socketPath_.empty()) {
        ::unlink(socketPath_.c_str());
        socketPath_.clear();
    }
    const std::string dir = runtime_dir();
    if (!make_dirs(dir)) {
        report(sys_error("mkdir runtime dir"));
        return reply;
    }
    socketPath_ = dir + "/tunbridge-helper-" + std::to_string(static_cast<long long>(getpid())) + ".sock";
    struct sockaddr_un addr{};
    if (socketPath_.size() + 1 > sizeof(addr.sun_path)) {
        report("Слишком длинный путь сокета помощника");
        disconnect();
        return reply;
    }

    listenFd_ = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (listenFd_ < 0) {
        report(sys_error("socket"));
        disconnect();
        return reply;
    }
    // The path is derived from our own pid; a leftover from a previous run is
    // always safe to remove before binding.
    ::unlink(socketPath_.c_str());
    std::memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    std::memcpy(addr.sun_path, socketPath_.c_str(), socketPath_.size());
    if (::bind(listenFd_, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) != 0) {
        report(sys_error("bind"));
        disconnect();
        return reply;
    }
    if (::chmod(socketPath_.c_str(), 0600) != 0) {
        report(sys_error("chmod"));
        disconnect();
        return reply;
    }
    if (::listen(listenFd_, 1) != 0) {
        report(sys_error("listen"));
        disconnect();
        return reply;
    }

    // No shell: pkexec is executed directly with an explicit argument vector.
    std::vector<std::string> args{"pkexec", helperPath, "--socket", socketPath_};
    std::vector<char*> argv;
    argv.reserve(args.size() + 1);
    for (const auto& a : args) argv.push_back(const_cast<char*>(a.c_str()));
    argv.push_back(nullptr);
    helperPid_ = ::fork();
    if (helperPid_ < 0) {
        report(sys_error("fork"));
        disconnect();
        return reply;
    }
    if (helperPid_ == 0) {
        ::execvp("pkexec", argv.data());
        ::_exit(127);
    }

    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::milliseconds(timeoutMs > 0 ? timeoutMs : 15000);
    fd_ = -1;
    for (;;) {
        struct pollfd pfd{};
        pfd.fd = listenFd_;
        pfd.events = POLLIN;
        const int wait = remaining_ms(deadline);
        const int rc = ::poll(&pfd, 1, wait);
        if (rc < 0) {
            if (errno == EINTR) continue;
            report(sys_error("poll"));
            disconnect();
            reap_helper(helperPid_);
            helperPid_ = -1;
            return reply;
        }
        if (rc == 0) {
            report("Тайм-аут ожидания помощника (pkexec)");
            disconnect();
            reap_helper(helperPid_);
            helperPid_ = -1;
            return reply;
        }
        fd_ = ::accept4(listenFd_, nullptr, nullptr, SOCK_CLOEXEC);
        if (fd_ >= 0) break;
        if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
        report(sys_error("accept"));
        disconnect();
        reap_helper(helperPid_);
        helperPid_ = -1;
        return reply;
    }

    ::close(listenFd_);
    listenFd_ = -1;
    const int left = std::max(1, static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(
        deadline - std::chrono::steady_clock::now()).count()));
    struct timeval tv{};
    tv.tv_sec = left / 1000;
    tv.tv_usec = (left % 1000) * 1000;
    ::setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    ::setsockopt(fd_, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    const std::string request = encode_request(r);
    if (!send_all(fd_, request, err)) {
        reply.message = err && !err->empty() ? *err : "Ошибка отправки запроса";
        disconnect();
        reap_helper(helperPid_);
        helperPid_ = -1;
        return reply;
    }
    std::string text;
    if (!read_frame(fd_, text, err)) {
        reply.message = err && !err->empty() ? *err : "Ошибка чтения ответа";
        disconnect();
        reap_helper(helperPid_);
        helperPid_ = -1;
        return reply;
    }
    if (!decode_reply(text, reply)) {
        report("Некорректный протокол ответа помощника");
        reply.ok = false;
        disconnect();
        reap_helper(helperPid_);
        helperPid_ = -1;
        return reply;
    }
    return reply;
}

void HelperClient::disconnect() {
    if (fd_ >= 0) {
        ::shutdown(fd_, SHUT_RDWR);
        ::close(fd_);
        fd_ = -1;
    }
    if (listenFd_ >= 0) {
        ::close(listenFd_);
        listenFd_ = -1;
    }
}

} // namespace tb

// Linux desktop system proxy integration.
//
// Detects the current desktop and applies a per-user proxy configuration:
//   * KDE (Plasma)      -> kioslaverc via kwriteconfig6 (direct edit fallback)
//   * GNOME family      -> gsettings (manual mode)
//   * everything else   -> ~/.config/tunbridge/proxy.env + systemd --user env
//
// All original values are captured before any change so disable() restores the
// exact previous state. External tools are launched with fork/execvp and
// argument vectors (never through a shell).

#include "tunbridge/system_proxy.hpp"

#include "tunbridge/xdg.hpp"

#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <map>
#include <string>
#include <thread>
#include <vector>

namespace tb {
namespace {

using Clock = std::chrono::steady_clock;

struct CmdResult {
    int code{-1};
    std::string out;
};

// fork + execvp, capture stdout/stderr, wait with a deadline. No shell is used.
CmdResult run_cmd(const std::vector<std::string>& args, int timeoutMs = 3000) {
    CmdResult res;
    if (args.empty()) return res;

    int pipeFd[2] = {-1, -1};
    if (::pipe(pipeFd) != 0) return res;
    int fl = ::fcntl(pipeFd[0], F_GETFL, 0);
    if (fl >= 0) ::fcntl(pipeFd[0], F_SETFL, fl | O_NONBLOCK);

    const pid_t pid = ::fork();
    if (pid < 0) {
        ::close(pipeFd[0]);
        ::close(pipeFd[1]);
        return res;
    }
    if (pid == 0) {
        ::close(pipeFd[0]);
        ::dup2(pipeFd[1], STDOUT_FILENO);
        ::dup2(pipeFd[1], STDERR_FILENO);
        if (pipeFd[1] > STDERR_FILENO) ::close(pipeFd[1]);
        std::vector<char*> argv;
        argv.reserve(args.size() + 1);
        for (const std::string& a : args) argv.push_back(const_cast<char*>(a.c_str()));
        argv.push_back(nullptr);
        ::execvp(argv[0], argv.data());
        ::_exit(127);
    }

    ::close(pipeFd[1]);
    const auto readDeadline = Clock::now() + std::chrono::milliseconds(timeoutMs);
    char buf[4096];
    for (;;) {
        const auto now = Clock::now();
        if (now >= readDeadline) break;
        int waitMs = static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(
            readDeadline - now).count());
        waitMs = std::min(waitMs, 100);
        struct pollfd pfd{};
        pfd.fd = pipeFd[0];
        pfd.events = POLLIN;
        const int r = ::poll(&pfd, 1, waitMs);
        if (r < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (r == 0) continue;
        const ssize_t n = ::read(pipeFd[0], buf, sizeof(buf));
        if (n > 0) {
            if (res.out.size() < 65536)
                res.out.append(buf, static_cast<std::size_t>(n));
        } else if (n == 0) {
            break;
        } else if (errno != EINTR && errno != EAGAIN) {
            break;
        }
    }
    ::close(pipeFd[0]);

    const auto waitDeadline = Clock::now() + std::chrono::milliseconds(1000);
    int status = 0;
    for (;;) {
        const pid_t r = ::waitpid(pid, &status, WNOHANG);
        if (r == pid) {
            res.code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
            break;
        }
        if (r < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (Clock::now() >= waitDeadline) {
            ::kill(pid, SIGKILL);
            ::waitpid(pid, &status, 0);
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return res;
}

std::string trimmed(std::string s) {
    const auto first = s.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return {};
    const auto last = s.find_last_not_of(" \t\r\n");
    return s.substr(first, last - first + 1);
}

std::string lower_copy(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

// Length-prefixed serialization: safe for values containing any character.
std::string pack(const std::vector<std::string>& parts) {
    std::string out;
    for (const std::string& s : parts) {
        out += std::to_string(s.size());
        out.push_back(':');
        out += s;
    }
    return out;
}

std::vector<std::string> unpack(const std::string& in) {
    std::vector<std::string> parts;
    std::size_t i = 0;
    while (i < in.size()) {
        const std::size_t colon = in.find(':', i);
        if (colon == std::string::npos) break;
        const std::size_t len = static_cast<std::size_t>(std::strtoul(in.c_str() + i, nullptr, 10));
        i = colon + 1;
        if (i + len > in.size()) break;
        parts.push_back(in.substr(i, len));
        i += len;
    }
    return parts;
}

bool ensure_dir(const std::string& path) {
    std::error_code ec;
    std::filesystem::create_directories(path, ec);
    if (ec && !std::filesystem::is_directory(path)) return false;
    ::chmod(path.c_str(), 0700);
    return std::filesystem::is_directory(path);
}

std::string detect_desktop() {
    std::string raw;
    for (const char* var : {"XDG_CURRENT_DESKTOP", "XDG_SESSION_DESKTOP", "DESKTOP_SESSION"}) {
        const char* v = std::getenv(var);
        if (v && *v) {
            raw = v;
            break;
        }
    }
    if (raw.empty() && std::getenv("KDE_FULL_SESSION") != nullptr) raw = "KDE";

    const std::string l = lower_copy(raw);
    if (l.find("kde") != std::string::npos) return "KDE";
    if (l.find("plasma") != std::string::npos) return "KDE";
    if (l.find("gnome") != std::string::npos || l.find("cinnamon") != std::string::npos ||
        l.find("budgie") != std::string::npos) {
        return "GNOME";
    }
    if (l.find("hyprland") != std::string::npos) return "Hyprland";
    if (l.find("sway") != std::string::npos) return "Sway";
    if (l.find("i3") != std::string::npos) return "i3";
    return raw.empty() ? std::string("unknown") : raw;
}

// ---------------------------------------------------------------- GNOME ----

std::string gs_get(const std::string& schema, const std::string& key) {
    const CmdResult r = run_cmd({"gsettings", "get", schema, key}, 2500);
    if (r.code != 0) return {};
    std::string v = trimmed(r.out);
    if (v.size() >= 2 && v.front() == '\'' && v.back() == '\'')
        v = v.substr(1, v.size() - 2);
    return v;
}

bool gs_set(const std::string& schema, const std::string& key, const std::string& value) {
    return run_cmd({"gsettings", "set", schema, key, value}, 3000).code == 0;
}

std::string gs_string(const std::string& v) { return "'" + v + "'"; }

void gs_restore(const std::string& schema, const std::string& key,
                const std::string& value, bool asString) {
    if (value.empty()) return;
    gs_set(schema, key, asString ? gs_string(value) : value);
}

bool gnome_enable(const std::string& url, int port, std::string& original) {
    const std::string gp = "org.gnome.system.proxy";
    original = pack({
        gs_get(gp, "mode"),
        gs_get(gp + ".http", "host"),
        gs_get(gp + ".http", "port"),
        gs_get(gp + ".https", "host"),
        gs_get(gp + ".https", "port"),
        gs_get(gp + ".ftp", "host"),
        gs_get(gp + ".ftp", "port"),
        gs_get(gp, "ignore-hosts"),
    });

    const std::string ignore =
        "['localhost', '127.0.0.1', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']";
    bool ok = true;
    ok = gs_set(gp, "mode", gs_string("manual")) && ok;
    ok = gs_set(gp + ".http", "host", gs_string("127.0.0.1")) && ok;
    ok = gs_set(gp + ".http", "port", std::to_string(port)) && ok;
    ok = gs_set(gp + ".https", "host", gs_string("127.0.0.1")) && ok;
    ok = gs_set(gp + ".https", "port", std::to_string(port)) && ok;
    ok = gs_set(gp + ".ftp", "host", gs_string("127.0.0.1")) && ok;
    ok = gs_set(gp + ".ftp", "port", std::to_string(port)) && ok;
    ok = gs_set(gp, "ignore-hosts", ignore) && ok;
    (void)url; // the GNOME schema stores host and port separately
    return ok;
}

void gnome_disable(const std::string& original) {
    const auto v = unpack(original);
    if (v.size() < 8) return;
    const std::string gp = "org.gnome.system.proxy";
    gs_restore(gp, "mode", v[0], true);
    gs_restore(gp + ".http", "host", v[1], true);
    gs_restore(gp + ".http", "port", v[2], false);
    gs_restore(gp + ".https", "host", v[3], true);
    gs_restore(gp + ".https", "port", v[4], false);
    gs_restore(gp + ".ftp", "host", v[5], true);
    gs_restore(gp + ".ftp", "port", v[6], false);
    gs_restore(gp, "ignore-hosts", v[7], false);
}

// ------------------------------------------------------------------- KDE ----

const char* const kKdeKeys[] = {"ProxyType", "httpProxy", "httpsProxy", "ftpProxy", "noProxyFor"};

struct KdeState {
    std::map<std::string, std::string> values;
    std::map<std::string, bool> present;
};

std::string kde_config_path() { return home_dir() + "/.config/kioslaverc"; }

KdeState kde_read() {
    KdeState st;
    std::ifstream f(kde_config_path());
    bool inGroup = false;
    std::string line;
    while (std::getline(f, line)) {
        const std::string t = trimmed(line);
        if (t.size() >= 2 && t.front() == '[' && t.back() == ']') {
            inGroup = (t == "[Proxy Settings]");
            continue;
        }
        if (!inGroup || t.empty() || t[0] == '#' || t[0] == ';') continue;
        const std::size_t eq = t.find('=');
        if (eq == std::string::npos) continue;
        const std::string key = trimmed(t.substr(0, eq));
        st.values[key] = trimmed(t.substr(eq + 1));
        st.present[key] = true;
    }
    return st;
}

bool kde_direct_set(const std::string& key, const std::string* value) {
    const std::string path = kde_config_path();
    if (!ensure_dir(home_dir() + "/.config")) return false;

    std::vector<std::string> lines;
    {
        std::ifstream f(path);
        std::string line;
        while (std::getline(f, line)) lines.push_back(line);
    }

    std::vector<std::string> out;
    out.reserve(lines.size() + 3);
    bool inGroup = false, groupFound = false, replaced = false;
    std::size_t insertAt = 0;

    for (const std::string& line : lines) {
        const std::string t = trimmed(line);
        if (t.size() >= 2 && t.front() == '[' && t.back() == ']') {
            if (inGroup) insertAt = out.size();
            inGroup = (t == "[Proxy Settings]");
            if (inGroup) {
                groupFound = true;
                insertAt = out.size() + 1;
            }
            out.push_back(line);
            continue;
        }
        if (inGroup && !t.empty() && t[0] != '#' && t[0] != ';') {
            const std::size_t eq = t.find('=');
            if (eq != std::string::npos && trimmed(t.substr(0, eq)) == key) {
                if (value != nullptr) out.push_back(key + "=" + *value);
                replaced = true;
                continue;
            }
        }
        out.push_back(line);
    }
    if (inGroup) insertAt = out.size();

    if (!replaced && value != nullptr) {
        if (!groupFound) {
            out.push_back("");
            out.push_back("[Proxy Settings]");
            insertAt = out.size();
        }
        out.insert(out.begin() + static_cast<std::ptrdiff_t>(insertAt), key + "=" + *value);
    }

    std::ofstream f(path, std::ios::trunc);
    if (!f) return false;
    for (const std::string& line : out) f << line << '\n';
    f.flush();
    return static_cast<bool>(f);
}

bool kde_write(const std::string& key, const std::string* value) {
    for (const char* tool : {"kwriteconfig6", "kwriteconfig5"}) {
        std::vector<std::string> args = {tool, "--file", "kioslaverc", "--group",
                                         "Proxy Settings", "--key", key};
        if (value != nullptr) args.push_back(*value);
        else args.push_back("--delete");
        if (run_cmd(args, 3000).code == 0) return true;
    }
    return kde_direct_set(key, value);
}

void kde_notify() {
    (void)run_cmd({"dbus-send", "--session", "--dest=org.kde.KIO.Slave",
                   "/KIO/Scheduler", "org.kde.KIO.Slave.reparseSlaveConfiguration"}, 2000);
    (void)run_cmd({"qdbus6", "org.kde.kioslave5", "/KIO/Scheduler",
                   "org.kde.KIO.Slave.reparseSlaveConfiguration"}, 2000);
}

bool kde_enable(const std::string& url, int port, std::string& original) {
    (void)port;
    const KdeState st = kde_read();
    std::vector<std::string> vals;
    for (const char* key : kKdeKeys) {
        const bool present = st.present.count(key) != 0;
        vals.push_back(present ? "1" : "0");
        vals.push_back(present ? st.values.at(key) : std::string{});
    }
    original = pack(vals);

    const std::string noProxy =
        "localhost,127.0.0.1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16";
    const std::string proxyType = "1";
    bool ok = true;
    ok = kde_write("ProxyType", &proxyType) && ok;
    ok = kde_write("httpProxy", &url) && ok;
    ok = kde_write("httpsProxy", &url) && ok;
    ok = kde_write("ftpProxy", &url) && ok;
    ok = kde_write("noProxyFor", &noProxy) && ok;
    kde_notify();
    return ok;
}

void kde_disable(const std::string& original) {
    const auto v = unpack(original);
    if (v.size() < 10) return;
    for (std::size_t i = 0; i < 5 && (i * 2 + 1) < v.size(); ++i) {
        if (v[i * 2] == "1") {
            std::string value = v[i * 2 + 1];
            (void)kde_write(kKdeKeys[i], &value);
        } else {
            (void)kde_write(kKdeKeys[i], nullptr);
        }
    }
    kde_notify();
}

// ------------------------------------------------------------- env fallback -

const char* const kEnvKeys[] = {"http_proxy", "https_proxy", "all_proxy", "no_proxy"};

std::string env_file() { return proxy_env_path(); }

std::map<std::string, std::string> systemd_environment() {
    std::map<std::string, std::string> env;
    for (const char* key : kEnvKeys) {
        const char* v = std::getenv(key);
        if (v && *v) env[key] = v;
    }
    const CmdResult r = run_cmd({"systemctl", "--user", "show-environment"}, 2500);
    // Parse "KEY=value" lines manually (systemd prints one per line).
    std::size_t pos = 0;
    while (pos < r.out.size()) {
        std::size_t end = r.out.find('\n', pos);
        if (end == std::string::npos) end = r.out.size();
        std::string line = r.out.substr(pos, end - pos);
        pos = end + 1;
        const std::size_t eq = line.find('=');
        if (eq == std::string::npos) continue;
        const std::string key = line.substr(0, eq);
        for (const char* wanted : kEnvKeys) {
            if (key == wanted) {
                env[key] = line.substr(eq + 1);
                break;
            }
        }
    }
    return env;
}

std::string env_original_state() {
    const std::string path = env_file();
    std::string fileContent;
    bool filePresent = false;
    {
        std::ifstream f(path, std::ios::binary);
        if (f) {
            fileContent.assign(std::istreambuf_iterator<char>(f),
                               std::istreambuf_iterator<char>());
            filePresent = true;
        }
    }

    const auto env = systemd_environment();
    std::vector<std::string> vals = {filePresent ? "1" : "0", filePresent ? fileContent : ""};
    for (const char* key : kEnvKeys) {
        const auto it = env.find(key);
        vals.push_back(it == env.end() ? "0" : "1");
        vals.push_back(it == env.end() ? std::string{} : it->second);
    }
    return pack(vals);
}

bool env_enable(const std::string& url, int port, std::string& original) {
    (void)port;
    original = env_original_state();

    const std::string noProxy =
        "localhost,127.0.0.1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16";
    const std::string content =
        "http_proxy=" + url + "\n" +
        "https_proxy=" + url + "\n" +
        "all_proxy=" + url + "\n" +
        "no_proxy=" + noProxy + "\n";

    if (!ensure_dir(config_home() + "/tunbridge")) return false;
    const std::string path = env_file();
    std::ofstream f(path, std::ios::trunc);
    if (!f) return false;
    f << content;
    f.flush();
    if (!f) return false;
    ::chmod(path.c_str(), 0600);

    (void)run_cmd({"systemctl", "--user", "set-environment",
                   "http_proxy=" + url, "https_proxy=" + url,
                   "all_proxy=" + url, "no_proxy=" + noProxy}, 3000);
    return true;
}

void env_disable(const std::string& original) {
    const auto v = unpack(original);
    if (v.size() < 10) return;

    std::vector<std::string> setArgs = {"systemctl", "--user", "set-environment"};
    std::vector<std::string> unsetArgs = {"systemctl", "--user", "unset-environment"};
    for (std::size_t i = 0; i < 4; ++i) {
        const std::string& present = v[2 + i * 2];
        const std::string& value = v[3 + i * 2];
        if (present == "1") setArgs.push_back(std::string(kEnvKeys[i]) + "=" + value);
        else unsetArgs.push_back(kEnvKeys[i]);
    }
    if (setArgs.size() > 3) (void)run_cmd(setArgs, 3000);
    if (unsetArgs.size() > 3) (void)run_cmd(unsetArgs, 3000);

    const std::string path = env_file();
    if (v[0] == "1") {
        std::ofstream f(path, std::ios::trunc);
        if (f) {
            f << v[1];
            f.flush();
            ::chmod(path.c_str(), 0600);
        }
    } else {
        std::error_code ec;
        (void)std::filesystem::remove(path, ec);
    }
}

} // namespace

bool SystemProxy::enable(int localPort, std::string* err) {
    const auto fail = [err](const char* msg) {
        if (err) *err = msg;
        return false;
    };
    if (localPort < 1 || localPort > 65535) return fail("invalid local port");

    if (changed_) disable(); // re-enable must start from a clean baseline
    desktop_ = detect_desktop();
    const std::string url = "http://127.0.0.1:" + std::to_string(localPort);

    bool ok = false;
    std::string primaryKey;
    std::string primaryOriginal;
    if (desktop_ == "KDE") {
        primaryKey = "kde";
        ok = kde_enable(url, localPort, primaryOriginal);
    } else if (desktop_ == "GNOME") {
        primaryKey = "gnome";
        ok = gnome_enable(url, localPort, primaryOriginal);
    }

    if (ok) {
        original_ = primaryOriginal;
        changedKey_ = primaryKey;
    } else {
        // Undo any partial primary change, then use the env fallback.
        if (primaryKey == "kde") kde_disable(primaryOriginal);
        else if (primaryKey == "gnome") gnome_disable(primaryOriginal);
        std::string envOriginal;
        if (!env_enable(url, localPort, envOriginal))
            return fail("failed to configure system proxy");
        original_ = envOriginal;
        changedKey_ = "env";
    }

    hint_ = url;
    changed_ = true;
    return true;
}

void SystemProxy::disable() {
    if (!changed_) return;
    if (changedKey_ == "kde") kde_disable(original_);
    else if (changedKey_ == "gnome") gnome_disable(original_);
    else if (changedKey_ == "env") env_disable(original_);
    changed_ = false;
    hint_.clear();
    original_.clear();
    changedKey_.clear();
}

} // namespace tb

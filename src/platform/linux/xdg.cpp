// XDG Base Directory backend for TunBridge configuration and autostart.
// Only standard C++20 + POSIX are used.

#include "tunbridge/xdg.hpp"

#include "tunbridge/core.hpp"

#include <pwd.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <map>
#include <sstream>
#include <string>

namespace tb {
namespace {

std::string trim_tail(std::string s) {
    while (s.size() > 1 && s.back() == '/') s.pop_back();
    return s;
}

std::string xdg_dir(const char* var, const std::string& fallback) {
    const char* v = std::getenv(var);
    if (v && *v && v[0] == '/') return trim_tail(v);
    return trim_tail(fallback);
}

bool ensure_dir(const std::string& path) {
    std::error_code ec;
    std::filesystem::create_directories(path, ec);
    if (ec && !std::filesystem::is_directory(path)) return false;
    ::chmod(path.c_str(), 0700);
    return std::filesystem::is_directory(path);
}

bool valid_port(int p) { return p >= 1 && p <= 65535; }

std::string map_get(const std::map<std::string, std::string>& m, const char* key,
                    const std::string& fallback) {
    const auto it = m.find(key);
    return it == m.end() ? fallback : it->second;
}

int map_get_int(const std::map<std::string, std::string>& m, const char* key,
                int fallback) {
    const auto it = m.find(key);
    if (it == m.end()) return fallback;
    try {
        std::size_t pos = 0;
        const long v = std::stol(it->second, &pos);
        if (pos != it->second.size()) return fallback;
        return static_cast<int>(v);
    } catch (...) {
        return fallback;
    }
}

bool parse_bool(const std::string& v) {
    std::string s = v;
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return s == "1" || s == "true" || s == "yes" || s == "on";
}

std::string desktop_file_path() {
    return config_home() + "/autostart/tunbridge.desktop";
}

std::string quote_exec_arg(const std::string& s) {
    std::string escaped;
    escaped.reserve(s.size() + 2);
    for (char c : s) {
        if (c == '"' || c == '\\' || c == '$' || c == '`') escaped.push_back('\\');
        escaped.push_back(c);
    }
    return '"' + escaped + '"';
}

} // namespace

std::string home_dir() {
    const char* h = std::getenv("HOME");
    if (h && *h) return trim_tail(h);
    struct passwd* pw = ::getpwuid(::getuid());
    if (pw && pw->pw_dir && *pw->pw_dir) return trim_tail(pw->pw_dir);
    return "/tmp";
}

std::string config_home() {
    return xdg_dir("XDG_CONFIG_HOME", home_dir() + "/.config");
}

std::string data_home() {
    return xdg_dir("XDG_DATA_HOME", home_dir() + "/.local/share");
}

std::string runtime_dir() {
    return xdg_dir("XDG_RUNTIME_DIR", home_dir() + "/.cache");
}

std::string config_path() {
    return config_home() + "/tunbridge/config.ini";
}

std::string proxy_env_path() {
    return config_home() + "/tunbridge/proxy.env";
}

bool load_app_config(AppConfig& out) {
    std::map<std::string, std::string> kv;
    if (!tb::ini_load(config_path(), kv)) return false;

    safe_copy(out.net.ip, sizeof(out.net.ip), map_get(kv, "ip", "").c_str());
    safe_copy(out.net.user, sizeof(out.net.user), map_get(kv, "user", "").c_str());
    safe_copy(out.net.pass, sizeof(out.net.pass), map_get(kv, "pass", "").c_str());

    const int socks = map_get_int(kv, "socks_port", out.net.socksPort);
    const int local = map_get_int(kv, "local_port", out.net.localPort);
    if (valid_port(socks)) out.net.socksPort = socks;
    if (valid_port(local)) out.net.localPort = local;

    const int mode = map_get_int(kv, "mode", static_cast<int>(out.mode));
    if (mode == 0 || mode == 1) out.mode = static_cast<Mode>(mode);

    out.minimizeToTray = parse_bool(map_get(kv, "minimize_to_tray", "1"));
    out.autoRestoreZapret = parse_bool(map_get(kv, "auto_restore_zapret", "0"));
    out.autoStart = parse_bool(map_get(kv, "autostart", "0"));
    return true;
}

bool save_app_config(const AppConfig& in) {
    if (!ensure_dir(config_home() + "/tunbridge")) return false;

    const int socks = valid_port(in.net.socksPort) ? in.net.socksPort : 10808;
    const int local = valid_port(in.net.localPort) ? in.net.localPort : 8888;

    std::map<std::string, std::string> kv;
    kv["ip"] = in.net.ip;
    kv["socks_port"] = std::to_string(socks);
    kv["user"] = in.net.user;
    kv["pass"] = in.net.pass;
    kv["local_port"] = std::to_string(local);
    kv["mode"] = std::to_string(static_cast<int>(in.mode) == 1 ? 1 : 0);
    kv["minimize_to_tray"] = in.minimizeToTray ? "1" : "0";
    kv["auto_restore_zapret"] = in.autoRestoreZapret ? "1" : "0";
    kv["autostart"] = in.autoStart ? "1" : "0";
    return tb::ini_save(config_path(), kv); // ini_save() applies mode 0600
}

bool set_autostart(bool enabled, const CliOptions& flags, const std::string& executable) {
    const std::string path = desktop_file_path();
    if (!enabled) {
        std::error_code ec;
        if (!std::filesystem::exists(path)) return true;
        return std::filesystem::remove(path, ec) && !ec;
    }

    if (!ensure_dir(config_home() + "/autostart")) return false;

    std::string exec;
    if (!executable.empty()) exec = quote_exec_arg(executable);
    if (flags.minimized) exec += " --minimized";
    if (flags.autostartTun) exec += " --autostart-tun";
    if (flags.downloadTun) exec += " --download-tun";
    if (flags.stopZapret) exec += " --stop-zapret";

    std::ostringstream contents;
    contents << "[Desktop Entry]\n"
             << "Type=Application\n"
             << "Name=TunBridge\n"
             << "Comment=Start TunBridge at login\n"
             << "Exec=" << exec << "\n"
             << "Terminal=false\n"
             << "X-GNOME-Autostart-enabled=true\n"
             << "NoDisplay=true\n";

    std::ofstream f(path, std::ios::trunc);
    if (!f) return false;
    f << contents.str();
    f.flush();
    if (!f) return false;
    ::chmod(path.c_str(), 0600);
    return true;
}

bool is_autostart_enabled() {
    const std::string path = desktop_file_path();
    std::error_code ec;
    if (!std::filesystem::exists(path, ec) || ec) return false;

    std::ifstream f(path);
    if (!f) return false;
    std::string line;
    while (std::getline(f, line)) {
        const std::size_t eq = line.find('=');
        if (eq == std::string::npos) continue;
        if (line.substr(0, eq) != "X-GNOME-Autostart-enabled") continue;
        const std::string v = line.substr(eq + 1);
        return parse_bool(v);
    }
    return true;
}

} // namespace tb

#pragma once

// Platform-independent TunBridge core types and helpers.
// Windows headers are deliberately not included here: both Win32 and POSIX
// front-ends consume the same data model.

#include <array>
#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <string_view>

namespace tb {

struct NetConfig {
    char ip[128]{};
    int socksPort{10808};
    char user[256]{};
    char pass[256]{};
    int localPort{8888};
};

struct ProbeResult {
    int32_t gen{0};
    int err{0};
    int pingMs{-1};
    int proto{1}; // 1 = SOCKS5, 2 = HTTP CONNECT
    bool fromTestBtn{false};
    char cc[4]{};
};

struct CliOptions {
    bool minimized{false};
    bool autostartTun{false};
    bool downloadTun{false};
    bool stopZapret{false};
};

enum class Mode : int { Proxy = 0, Tun = 1 };
enum class UpstreamProto : int { Auto = 0, Socks5 = 1, HttpConnect = 2 };
enum class NetEngineError : int {
    Ok = 0,
    Bind = 1,
    UpstreamUnreachable = 2,
    NotProxy = 3,
    BadCredentials = 4,
    Request = 5,
};

void safe_copy(char* dst, std::size_t n, const char* src);
bool is_safe_host(std::string_view s);

CliOptions parse_cli(int argc, char** argv);
bool cli_has_flag(const CliOptions& o, std::string_view flag);

// SHA-256 of a file. Uses WinCrypt on Windows and OpenSSL EVP on POSIX.
bool sha256_file_hex(const std::string& path, char outHex[65]);

// proxy URL for tun2socks, e.g. socks5://user:pass@1.2.3.4:1080
std::string url_encode(std::string_view s);
std::string proxy_url(const NetConfig& c, UpstreamProto proto);
std::string basic_auth_header(std::string_view user, std::string_view pass);

// HTTP request-line / Host header parser.
bool parse_host_port(std::string_view in, std::string& host, std::uint16_t& port,
                     std::uint16_t defaultPort);
int http_status_code(std::string_view headers);

// Tiny INI reader/writer used by the XDG config backend.
bool ini_load(const std::string& path, std::map<std::string, std::string>& out);
bool ini_save(const std::string& path, const std::map<std::string, std::string>& in);

} // namespace tb

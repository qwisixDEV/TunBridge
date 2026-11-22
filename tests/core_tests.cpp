// Standalone assert-style tests for the platform-independent TunBridge core.
// No external test framework is used: every check prints PASS/FAIL and the
// process returns non-zero if at least one check failed.

#include <tunbridge/core.hpp>

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <string>

namespace {

int g_failures = 0;
int g_passes = 0;

#define CHECK(cond, name)                                                        \
    do {                                                                         \
        if (cond) {                                                              \
            ++g_passes;                                                          \
            std::cout << "[PASS] " << name << '\n';                              \
        } else {                                                                 \
            ++g_failures;                                                        \
            std::cout << "[FAIL] " << name << " (line " << __LINE__ << ")\n";    \
        }                                                                        \
    } while (false)

struct TempDir {
    std::filesystem::path path;

    TempDir() {
        const auto base = std::filesystem::temp_directory_path();
        const auto stamp = std::chrono::steady_clock::now().time_since_epoch().count();
        for (int i = 0; i < 100; ++i) {
            path = base / ("tunbridge-tests-" + std::to_string(stamp) + "-" + std::to_string(i));
            if (std::filesystem::create_directory(path)) return;
        }
        path.clear();
    }

    ~TempDir() {
        if (path.empty()) return;
        std::error_code ec;
        std::filesystem::remove_all(path, ec);
    }

    TempDir(const TempDir&) = delete;
    TempDir& operator=(const TempDir&) = delete;
};

void test_parse_cli() {
    char arg0[] = "tunbridge";
    char a1[] = "--minimized";
    char a2[] = "--autostart-tun";
    char a3[] = "--download-tun";
    char a4[] = "--stop-zapret";
    char a5[] = "--unknown";

    char* all[] = {arg0, a1, a2, a3, a4, a5};
    const tb::CliOptions o = tb::parse_cli(6, all);
    CHECK(o.minimized && o.autostartTun && o.downloadTun && o.stopZapret,
          "parse_cli recognises all known flags");
    CHECK(tb::cli_has_flag(o, "--stop-zapret") && !tb::cli_has_flag(o, "--bogus"),
          "cli_has_flag");

    char* none[] = {arg0};
    const tb::CliOptions empty = tb::parse_cli(1, none);
    CHECK(!empty.minimized && !empty.autostartTun && !empty.downloadTun && !empty.stopZapret,
          "parse_cli defaults with no arguments");
}

void test_parse_host_port() {
    std::string host;
    std::uint16_t port = 0;

    CHECK(tb::parse_host_port("example.com:8080", host, port, 80) &&
              host == "example.com" && port == 8080,
          "parse_host_port host with explicit port");
    CHECK(tb::parse_host_port("example.com", host, port, 80) &&
              host == "example.com" && port == 80,
          "parse_host_port uses default port");
    CHECK(tb::parse_host_port("[2001:db8::1]:443", host, port, 80) &&
              host == "2001:db8::1" && port == 443,
          "parse_host_port IPv6 literal");
    CHECK(!tb::parse_host_port("", host, port, 80),
          "parse_host_port rejects empty input");
    CHECK(tb::parse_host_port("example.com:notaport", host, port, 80) && port == 80,
          "parse_host_port keeps default on invalid port");
    CHECK(tb::parse_host_port("example.com:99999", host, port, 80) && port == 80,
          "parse_host_port rejects out-of-range port");
}

void test_http_status_code() {
    CHECK(tb::http_status_code("HTTP/1.1 200 Connection established\r\n\r\n") == 200,
          "http_status_code 200");
    CHECK(tb::http_status_code("HTTP/1.1 407 Proxy Authentication Required\r\n") == 407,
          "http_status_code 407");
    CHECK(tb::http_status_code("not a status line") == 0,
          "http_status_code invalid input");
}

void test_url_encode() {
    CHECK(tb::url_encode("a b+c/d?e=f") == "a%20b%2Bc%2Fd%3Fe%3Df",
          "url_encode escapes unsafe characters");
    CHECK(tb::url_encode("Az09-_.~") == "Az09-_.~",
          "url_encode keeps unreserved characters");
}

void test_basic_auth_header() {
    CHECK(tb::basic_auth_header("user", "pass") ==
              "Proxy-Authorization: Basic dXNlcjpwYXNz\r\n",
          "basic_auth_header user:pass");
    CHECK(tb::basic_auth_header("", "") ==
              "Proxy-Authorization: Basic Og==\r\n",
          "basic_auth_header empty credentials");
}

void test_is_safe_host() {
    CHECK(tb::is_safe_host("example.com") && tb::is_safe_host("192.168.0.1") &&
              tb::is_safe_host("host-name") && tb::is_safe_host("[abcd]"),
          "is_safe_host accepts hostnames, IPs and bracketed tokens");
    // Colon is not part of the allowed set: parse_host_port strips the port first.
    CHECK(!tb::is_safe_host("host/path") && !tb::is_safe_host("bad host") &&
              !tb::is_safe_host("") && !tb::is_safe_host("user@host") &&
              !tb::is_safe_host("[::1]"),
          "is_safe_host rejects unsafe input");
}

void test_ini_roundtrip(const TempDir& dir) {
    const std::string path = (dir.path / "settings.ini").string();
    const std::map<std::string, std::string> expected{
        {"ip", "127.0.0.1"}, {"socksPort", "1080"}, {"user", "u@example.org"}};

    CHECK(tb::ini_save(path, expected), "ini_save writes file");
    std::map<std::string, std::string> actual;
    CHECK(tb::ini_load(path, actual), "ini_load reads file");
    CHECK(actual == expected, "ini_save/ini_load roundtrip");

    std::map<std::string, std::string> unused;
    CHECK(!tb::ini_load((dir.path / "does-not-exist.ini").string(), unused),
          "ini_load fails for missing file");
}

void test_sha256_file_hex(const TempDir& dir) {
    const std::string path = (dir.path / "abc.bin").string();
    {
        std::ofstream f(path, std::ios::binary | std::ios::trunc);
        f << "abc";
    }

    char hex[65]{};
    CHECK(tb::sha256_file_hex(path, hex), "sha256_file_hex succeeds");
    CHECK(std::string(hex) ==
              "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
          "sha256_file_hex of \"abc\"");
    CHECK(!tb::sha256_file_hex((dir.path / "missing.bin").string(), hex),
          "sha256_file_hex fails for missing file");
}

} // namespace

int main() {
    test_parse_cli();
    test_parse_host_port();
    test_http_status_code();
    test_url_encode();
    test_basic_auth_header();
    test_is_safe_host();

    TempDir dir;
    if (dir.path.empty()) {
        std::cout << "[FAIL] create temporary directory\n";
        ++g_failures;
    } else {
        test_ini_roundtrip(dir);
        test_sha256_file_hex(dir);
    }

    std::cout << "Results: " << g_passes << " passed, " << g_failures << " failed\n";
    return g_failures == 0 ? 0 : 1;
}

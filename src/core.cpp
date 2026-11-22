#include "tunbridge/core.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>

#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#else
#include <openssl/evp.h>
#include <sys/stat.h>
#endif

namespace tb {

void safe_copy(char* dst, std::size_t n, const char* src) {
    if (!dst || n == 0) return;
    if (!src) { dst[0] = 0; return; }
    std::size_t i = 0;
    for (; i + 1 < n && src[i]; ++i) dst[i] = src[i];
    dst[i] = 0;
}

bool is_safe_host(std::string_view s) {
    if (s.empty()) return false;
    for (char ch : s) {
        const unsigned char c = static_cast<unsigned char>(ch);
        const bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') ||
                        (c >= 'A' && c <= 'Z') || c == '.' || c == '-' || c == '[' || c == ']';
        if (!ok) return false;
    }
    return true;
}

CliOptions parse_cli(int argc, char** argv) {
    CliOptions o;
    for (int i = 1; i < argc; ++i) {
        if (!argv[i]) continue;
        const std::string_view a(argv[i]);
        if (a == "--minimized") o.minimized = true;
        else if (a == "--autostart-tun") o.autostartTun = true;
        else if (a == "--download-tun") o.downloadTun = true;
        else if (a == "--stop-zapret") o.stopZapret = true;
    }
    return o;
}

bool cli_has_flag(const CliOptions& o, std::string_view flag) {
    if (flag == "--minimized") return o.minimized;
    if (flag == "--autostart-tun") return o.autostartTun;
    if (flag == "--download-tun") return o.downloadTun;
    if (flag == "--stop-zapret") return o.stopZapret;
    return false;
}

bool sha256_file_hex(const std::string& path, char outHex[65]) {
    if (!outHex) return false;
    outHex[0] = 0;
    unsigned char digest[32]{};
    bool ok = false;

#ifdef _WIN32
    HANDLE hf = ::CreateFileW(std::filesystem::path(path).wstring().c_str(), GENERIC_READ,
                              FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                              FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (hf == INVALID_HANDLE_VALUE) return false;
    HCRYPTPROV prov = 0;
    HCRYPTHASH hash = 0;
    if (::CryptAcquireContextW(&prov, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        if (::CryptCreateHash(prov, CALG_SHA_256, 0, 0, &hash)) {
            unsigned char buf[32768];
            DWORD read = 0, digestLen = 32;
            bool readOk = true;
            while (::ReadFile(hf, buf, sizeof(buf), &read, nullptr) && read > 0) {
                if (!::CryptHashData(hash, buf, read, 0)) { readOk = false; break; }
            }
            if (readOk && ::CryptGetHashParam(hash, HP_HASHVAL, digest, &digestLen, 0) &&
                digestLen == 32)
                ok = true;
            ::CryptDestroyHash(hash);
        }
        ::CryptReleaseContext(prov, 0);
    }
    ::CloseHandle(hf);
#else
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx && EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) == 1) {
        std::FILE* f = std::fopen(path.c_str(), "rb");
        if (f) {
            std::array<unsigned char, 32768> buf{};
            bool hashOk = true;
            for (;;) {
                const std::size_t n = std::fread(buf.data(), 1, buf.size(), f);
                if (n > 0 && EVP_DigestUpdate(ctx, buf.data(), n) != 1) { hashOk = false; break; }
                if (n < buf.size()) break;
            }
            unsigned int len = 0;
            if (hashOk && !std::ferror(f) && EVP_DigestFinal_ex(ctx, digest, &len) == 1 && len == 32)
                ok = true;
            std::fclose(f);
        }
    }
    if (ctx) EVP_MD_CTX_free(ctx);
#endif

    if (!ok) return false;
    static const char hex[] = "0123456789abcdef";
    for (int i = 0; i < 32; ++i) {
        outHex[i * 2] = hex[digest[i] >> 4];
        outHex[i * 2 + 1] = hex[digest[i] & 15];
    }
    outHex[64] = 0;
    return true;
}

std::string url_encode(std::string_view s) {
    static const char hex[] = "0123456789ABCDEF";
    std::string out;
    out.reserve(s.size());
    for (char ch : s) {
        const unsigned char c = static_cast<unsigned char>(ch);
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~')
            out.push_back(static_cast<char>(c));
        else {
            out.push_back('%');
            out.push_back(hex[c >> 4]);
            out.push_back(hex[c & 15]);
        }
    }
    return out;
}

std::string proxy_url(const NetConfig& c, UpstreamProto proto) {
    const char* scheme = proto == UpstreamProto::HttpConnect ? "http" : "socks5";
    std::string url = scheme;
    url += "://";
    if (c.user[0] || c.pass[0]) {
        url += url_encode(c.user);
        url += ':';
        url += url_encode(c.pass);
        url += '@';
    }
    url += c.ip;
    url += ':';
    url += std::to_string(c.socksPort);
    return url;
}

std::string basic_auth_header(std::string_view user, std::string_view pass) {
    static const char tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string creds(user);
    creds.push_back(':');
    creds.append(pass);
    std::string out = "Proxy-Authorization: Basic ";
    std::size_t i = 0;
    for (; i < creds.size(); i += 3) {
        const unsigned v = (static_cast<unsigned>(static_cast<unsigned char>(creds[i])) << 16) |
                           ((i + 1 < creds.size() ? static_cast<unsigned>(static_cast<unsigned char>(creds[i + 1])) : 0u) << 8) |
                           (i + 2 < creds.size() ? static_cast<unsigned>(static_cast<unsigned char>(creds[i + 2])) : 0u);
        out.push_back(tbl[(v >> 18) & 63]);
        out.push_back(tbl[(v >> 12) & 63]);
        out.push_back(i + 1 < creds.size() ? tbl[(v >> 6) & 63] : '=');
        out.push_back(i + 2 < creds.size() ? tbl[v & 63] : '=');
    }
    out += "\r\n";
    return out;
}

bool parse_host_port(std::string_view in, std::string& host, std::uint16_t& port,
                     std::uint16_t defaultPort) {
    host.clear();
    port = defaultPort;
    if (in.empty()) return false;
    if (in.front() == '[') {
        const std::size_t end = in.find(']');
        if (end == std::string_view::npos) return false;
        host.assign(in.substr(1, end - 1));
        if (end + 1 < in.size() && in[end + 1] == ':') {
            try {
                port = static_cast<std::uint16_t>(std::stoul(std::string(in.substr(end + 2))));
            } catch (...) { /* keep default */ }
        }
        return !host.empty();
    }
    const std::size_t colon = in.rfind(':');
    if (colon == std::string_view::npos) {
        host.assign(in);
    } else {
        host.assign(in.substr(0, colon));
        const std::string ps(in.substr(colon + 1));
        if (!ps.empty()) {
            try {
                const unsigned long p = std::stoul(ps);
                if (p > 0 && p <= 65535) port = static_cast<std::uint16_t>(p);
            } catch (...) { /* keep default */ }
        }
    }
    return !host.empty();
}

int http_status_code(std::string_view headers) {
    if (headers.size() < 12) return 0;
    const std::size_t sp = headers.find(' ');
    if (sp == std::string_view::npos || sp + 1 >= headers.size()) return 0;
    int code = 0;
    for (std::size_t i = sp + 1; i < headers.size() && headers[i] >= '0' && headers[i] <= '9'; ++i)
        code = code * 10 + (headers[i] - '0');
    return code;
}

namespace {
std::string_view trimmed(std::string_view s) {
    const auto first = s.find_first_not_of(" \t\r\n");
    if (first == std::string_view::npos) return {};
    const auto last = s.find_last_not_of(" \t\r\n");
    return s.substr(first, last - first + 1);
}
} // namespace

bool ini_load(const std::string& path, std::map<std::string, std::string>& out) {
    std::ifstream f(path);
    if (!f) return false;
    std::string line;
    while (std::getline(f, line)) {
        const std::string_view v = trimmed(line);
        if (v.empty() || v.front() == '#' || v.front() == ';' || v.front() == '[') continue;
        const std::size_t eq = v.find_first_of("=:");
        if (eq == std::string_view::npos) continue;
        std::string key(trimmed(v.substr(0, eq)));
        std::string value(trimmed(v.substr(eq + 1)));
        if (!key.empty()) out[key] = value;
    }
    return true;
}

bool ini_save(const std::string& path, const std::map<std::string, std::string>& in) {
    std::ofstream f(path, std::ios::trunc);
    if (!f) return false;
    f << "[tunbridge]\n";
    for (const auto& kv : in) f << kv.first << '=' << kv.second << '\n';
    f.flush();
#ifdef _WIN32
    return static_cast<bool>(f);
#else
    ::chmod(path.c_str(), 0600);
    return static_cast<bool>(f);
#endif
}

} // namespace tb

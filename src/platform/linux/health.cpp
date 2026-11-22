#include "tunbridge/health.hpp"

#include "tunbridge/upstream.hpp"

#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <chrono>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

namespace tb {
namespace {

class Deadline {
public:
    explicit Deadline(int timeoutMs) {
        const int ms = timeoutMs > 0 ? timeoutMs : 1;
        end_ = Clock::now() + std::chrono::milliseconds(ms);
    }
    int remaining_ms() const {
        if (Clock::now() >= end_) return 0;
        const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(end_ - Clock::now());
        return left.count() > 0 ? static_cast<int>(left.count()) : 0;
    }
private:
    using Clock = std::chrono::steady_clock;
    Clock::time_point end_;
};

bool wait_readable(int fd, Deadline& deadline) {
    struct pollfd p{};
    p.fd = fd;
    p.events = POLLIN;
    for (;;) {
        const int r = ::poll(&p, 1, deadline.remaining_ms());
        if (r > 0) return true;
        if (r == 0) return false;
        if (errno == EINTR) continue;
        return false;
    }
}

bool wait_writable(int fd, Deadline& deadline) {
    struct pollfd p{};
    p.fd = fd;
    p.events = POLLOUT;
    for (;;) {
        const int r = ::poll(&p, 1, deadline.remaining_ms());
        if (r > 0) return true;
        if (r == 0) return false;
        if (errno == EINTR) continue;
        return false;
    }
}

bool send_all(int fd, std::string_view data, Deadline& deadline) {
    std::size_t off = 0;
    while (off < data.size()) {
        if (!wait_writable(fd, deadline)) return false;
        const ssize_t n = ::send(fd, data.data() + off, data.size() - off, MSG_NOSIGNAL);
        if (n > 0) {
            off += static_cast<std::size_t>(n);
            continue;
        }
        if (n < 0 && errno == EINTR) continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) continue;
        return false;
    }
    return true;
}

std::size_t header_end(const char* data, std::size_t len) {
    for (std::size_t i = 0; i + 4 <= len; ++i) {
        if (data[i] == '\r' && data[i + 1] == '\n' &&
            data[i + 2] == '\r' && data[i + 3] == '\n')
            return i;
    }
    return static_cast<std::size_t>(-1);
}

// Returns true when a complete header block was received.
bool recv_headers(int fd, char* buf, std::size_t cap, std::size_t* outLen, Deadline& deadline) {
    std::size_t total = 0;
    while (total < cap) {
        if (!wait_readable(fd, deadline)) break;
        const ssize_t n = ::recv(fd, buf + total, cap - total, 0);
        if (n > 0) {
            total += static_cast<std::size_t>(n);
            if (header_end(buf, total) != static_cast<std::size_t>(-1)) {
                if (outLen) *outLen = total;
                return true;
            }
            continue;
        }
        if (n == 0) break;
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
        break;
    }
    if (outLen) *outLen = total;
    return false;
}

// Reads a body until EOF (Connection: close) or the deadline/capacity is hit.
std::size_t recv_body(int fd, char* buf, std::size_t cap, Deadline& deadline) {
    std::size_t total = 0;
    while (total < cap && deadline.remaining_ms() > 0) {
        if (!wait_readable(fd, deadline)) break;
        const ssize_t n = ::recv(fd, buf + total, cap - total, 0);
        if (n > 0) {
            total += static_cast<std::size_t>(n);
            continue;
        }
        if (n == 0) break;
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
        break;
    }
    return total;
}

bool contains_ci(std::string_view haystack, std::string_view needle) {
    if (needle.empty() || needle.size() > haystack.size()) return false;
    for (std::size_t i = 0; i + needle.size() <= haystack.size(); ++i) {
        bool match = true;
        for (std::size_t j = 0; j < needle.size(); ++j) {
            const unsigned char a = static_cast<unsigned char>(haystack[i + j]);
            const unsigned char b = static_cast<unsigned char>(needle[j]);
            if (std::tolower(a) != std::tolower(b)) {
                match = false;
                break;
            }
        }
        if (match) return true;
    }
    return false;
}

bool is_country_at(const char* p, std::size_t available) {
    if (available < 2) return false;
    const unsigned char a = static_cast<unsigned char>(p[0]);
    const unsigned char b = static_cast<unsigned char>(p[1]);
    if (a < 'A' || a > 'Z' || b < 'A' || b > 'Z') return false;
    if (available == 2) return true;
    return p[2] == '\r' || p[2] == '\n' || p[2] == ' ';
}

int map_error(NetEngineError err) {
    switch (err) {
    case NetEngineError::Ok: return 0;
    case NetEngineError::NotProxy: return 2;
    case NetEngineError::BadCredentials: return 3;
    default: return 4; // unreachable / request failure: no VPN or no network.
    }
}

int measured_ms(std::chrono::steady_clock::time_point from,
                std::chrono::steady_clock::time_point to) {
    int ms = static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(to - from).count());
    if (ms < 1) ms = 1;
    if (ms > 9999) ms = 9999;
    return ms;
}

} // namespace

HealthResult probe_health(const NetConfig& cfg, int timeoutMs) {
    HealthResult result;
    result.proto = UpstreamProto::Socks5;

    UpstreamResult up = connect_upstream_blocking(cfg, "cp.cloudflare.com", 80, timeoutMs,
                                                  UpstreamProto::Auto);
    if (up.err != NetEngineError::Ok || up.fd < 0) {
        result.err = map_error(up.err);
        return result;
    }
    result.proto = up.proto;
    const int fd = up.fd;
    struct timeval tv{};
    tv.tv_sec = timeoutMs > 0 ? timeoutMs / 1000 : 5;
    tv.tv_usec = static_cast<decltype(tv.tv_usec)>((timeoutMs > 0 ? timeoutMs % 1000 : 5000) * 1000);
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    Deadline deadline(timeoutMs);
    constexpr std::string_view kHead =
        "HEAD /generate_204 HTTP/1.1\r\nHost: cp.cloudflare.com\r\nConnection: keep-alive\r\n\r\n";
    std::array<char, 1024> first{};
    std::size_t firstLen = 0;

    const auto t0 = std::chrono::steady_clock::now();
    if (!send_all(fd, kHead, deadline) ||
        !recv_headers(fd, first.data(), first.size(), &firstLen, deadline)) {
        result.err = 4;
        ::close(fd);
        return result;
    }
    result.pingMs = measured_ms(t0, std::chrono::steady_clock::now());

    const std::string_view firstResponse(first.data(), firstLen);
    if (!contains_ci(firstResponse, "close")) {
        std::array<char, 1024> second{};
        std::size_t secondLen = 0;
        const auto t1 = std::chrono::steady_clock::now();
        if (send_all(fd, kHead, deadline) &&
            recv_headers(fd, second.data(), second.size(), &secondLen, deadline)) {
            result.pingMs = measured_ms(t1, std::chrono::steady_clock::now());

            constexpr std::string_view kTrace =
                "GET /cdn-cgi/trace HTTP/1.1\r\nHost: cp.cloudflare.com\r\n"
                "User-Agent: TunBridge/1.0\r\nConnection: close\r\n\r\n";
            if (send_all(fd, kTrace, deadline)) {
                std::array<char, 2048> body{};
                const std::size_t bodyLen = recv_body(fd, body.data(), body.size() - 1, deadline);
                const std::string_view text(body.data(), bodyLen);
                const std::size_t pos = text.find("loc=");
                if (pos != std::string_view::npos && pos + 5 < text.size()) {
                    const char* p = body.data() + pos + 4;
                    const std::size_t available = bodyLen - (pos + 4);
                    if (is_country_at(p, available)) {
                        result.country.assign(p, 2);
                    }
                }
            }
        }
    }
    ::close(fd);

    if (result.country.empty()) {
        UpstreamResult geo = connect_upstream_blocking(cfg, "ip-api.com", 80, timeoutMs,
                                                       UpstreamProto::Auto);
        if (geo.err == NetEngineError::Ok && geo.fd >= 0) {
            Deadline geoDeadline(timeoutMs);
            constexpr std::string_view kGeo =
                "GET /line/?fields=countryCode HTTP/1.0\r\nHost: ip-api.com\r\n"
                "User-Agent: TunBridge/1.0\r\nConnection: close\r\n\r\n";
            if (send_all(geo.fd, kGeo, geoDeadline)) {
                std::array<char, 1024> response{};
                const std::size_t len = recv_body(geo.fd, response.data(), response.size() - 1,
                                                  geoDeadline);
                const std::string_view text(response.data(), len);
                const std::size_t status = text.find("200 OK");
                const std::size_t split = text.find("\r\n\r\n");
                if (status != std::string_view::npos && split != std::string_view::npos &&
                    split + 4 <= text.size()) {
                    std::size_t pos = split + 4;
                    while (pos < text.size() &&
                           (text[pos] == ' ' || text[pos] == '\r' || text[pos] == '\n' ||
                            text[pos] == '\t'))
                        ++pos;
                    if (pos < text.size() &&
                        is_country_at(response.data() + pos, text.size() - pos))
                        result.country.assign(response.data() + pos, 2);
                }
            }
            ::close(geo.fd);
        }
    }

    result.err = 0;
    return result;
}

} // namespace tb

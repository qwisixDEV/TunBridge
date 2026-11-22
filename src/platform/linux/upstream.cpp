#include "tunbridge/upstream.hpp"

#include "tunbridge/core.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <utility>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif
#ifndef SOCK_CLOEXEC
#define SOCK_CLOEXEC O_CLOEXEC
#endif

namespace tb {
namespace {

class Deadline {
public:
    explicit Deadline(int timeoutMs) {
        const int ms = timeoutMs > 0 ? timeoutMs : 1;
        end_ = Clock::now() + std::chrono::milliseconds(ms);
    }

    bool expired() const { return Clock::now() >= end_; }

    int remaining_ms() const {
        if (expired()) return 0;
        const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(end_ - Clock::now());
        const long long v = left.count();
        if (v <= 0) return 0;
        return v > 1000000LL ? 1000000 : static_cast<int>(v);
    }

private:
    using Clock = std::chrono::steady_clock;
    Clock::time_point end_;
};

bool wait_ready(int fd, short events, Deadline& deadline) {
    struct pollfd p{};
    p.fd = fd;
    p.events = events;
    for (;;) {
        const int remaining = deadline.remaining_ms();
        const int r = ::poll(&p, 1, remaining);
        if (r > 0) return true;
        if (r == 0) return false;
        if (errno == EINTR) continue;
        return false;
    }
}

bool send_all_timeout(int fd, const char* data, std::size_t len, Deadline& deadline) {
    std::size_t off = 0;
    while (off < len) {
        if (!wait_ready(fd, POLLOUT, deadline)) return false;
        const ssize_t n = ::send(fd, data + off, len - off, MSG_NOSIGNAL);
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

bool recv_exact_timeout(int fd, char* data, std::size_t len, Deadline& deadline) {
    std::size_t off = 0;
    while (off < len) {
        if (!wait_ready(fd, POLLIN, deadline)) return false;
        const ssize_t n = ::recv(fd, data + off, len - off, 0);
        if (n > 0) {
            off += static_cast<std::size_t>(n);
            continue;
        }
        if (n == 0) return false;
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
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

bool recv_headers_timeout(int fd, char* buf, std::size_t cap, std::size_t* outLen,
                          Deadline& deadline) {
    std::size_t total = 0;
    while (total < cap) {
        if (!wait_ready(fd, POLLIN, deadline)) break;
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

bool resolve_peer(const char* host, std::uint16_t port, sockaddr_storage& out,
                  socklen_t& outLen) {
    struct sockaddr_in v4{};
    if (host && ::inet_pton(AF_INET, host, &v4.sin_addr) == 1) {
        v4.sin_family = AF_INET;
        v4.sin_port = htons(port);
        std::memcpy(&out, &v4, sizeof(v4));
        outLen = static_cast<socklen_t>(sizeof(v4));
        return true;
    }
    struct addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_ADDRCONFIG;
    struct addrinfo* res = nullptr;
    const std::string service = std::to_string(port);
    if (!host || ::getaddrinfo(host, service.c_str(), &hints, &res) != 0 || !res)
        return false;
    if (res->ai_addrlen > sizeof(out)) {
        ::freeaddrinfo(res);
        return false;
    }
    std::memcpy(&out, res->ai_addr, res->ai_addrlen);
    outLen = static_cast<socklen_t>(res->ai_addrlen);
    ::freeaddrinfo(res);
    return true;
}

int connect_tcp_timeout(const char* ip, std::uint16_t port, int timeoutMs) {
    sockaddr_storage addr{};
    socklen_t addrLen = 0;
    if (!resolve_peer(ip, port, addr, addrLen)) return -1;

    const int fd = ::socket(addr.ss_family, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    const int flags = ::fcntl(fd, F_GETFL, 0);
    if (flags < 0 || ::fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        ::close(fd);
        return -1;
    }
    const int rc = ::connect(fd, reinterpret_cast<struct sockaddr*>(&addr), addrLen);
    if (rc < 0 && errno != EINPROGRESS && errno != EALREADY) {
        ::close(fd);
        return -1;
    }
    if (rc < 0) {
        Deadline deadline(timeoutMs);
        if (!wait_ready(fd, POLLOUT, deadline)) {
            ::close(fd);
            return -1;
        }
        int soError = 0;
        socklen_t len = static_cast<socklen_t>(sizeof(soError));
        if (::getsockopt(fd, SOL_SOCKET, SO_ERROR, &soError, &len) < 0 || soError != 0) {
            ::close(fd);
            return -1;
        }
    }
    if (flags >= 0) ::fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
    const int one = 1;
    ::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    struct timeval tv{};
    tv.tv_sec = timeoutMs > 0 ? timeoutMs / 1000 : 0;
    tv.tv_usec = static_cast<decltype(tv.tv_usec)>((timeoutMs > 0 ? timeoutMs % 1000 : 0) * 1000);
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    return fd;
}

void make_plain_blocking(int fd) {
    const int flags = ::fcntl(fd, F_GETFL, 0);
    if (flags >= 0) ::fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
    struct timeval zero{};
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &zero, sizeof(zero));
    ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &zero, sizeof(zero));
}

bool has_credentials(const NetConfig& cfg) {
    return cfg.user[0] != '\0' || cfg.pass[0] != '\0';
}

// Greeting + optional user/pass authentication. Used by test_upstream() where
// no CONNECT is needed (mirrors the original TestUpstreamAuthAndProto()).
NetEngineError socks5_authenticate(int fd, const NetConfig& cfg, Deadline& deadline) {
    std::array<char, 4> greeting{};
    std::size_t greetingLen = 3;
    greeting[0] = 5;
    greeting[1] = has_credentials(cfg) ? 2 : 1;
    greeting[2] = 0;
    if (has_credentials(cfg)) {
        greeting[3] = 2;
        greetingLen = 4;
    }
    if (!send_all_timeout(fd, greeting.data(), greetingLen, deadline))
        return NetEngineError::NotProxy;

    std::array<char, 2> reply{};
    if (!recv_exact_timeout(fd, reply.data(), reply.size(), deadline) ||
        static_cast<unsigned char>(reply[0]) != 5)
        return NetEngineError::NotProxy;

    const unsigned char method = static_cast<unsigned char>(reply[1]);
    if (method == 0) return NetEngineError::Ok;
    if (method != 2 || !has_credentials(cfg)) return NetEngineError::BadCredentials;

    const std::size_t ul = std::min(std::strlen(cfg.user), static_cast<std::size_t>(255));
    const std::size_t pl = std::min(std::strlen(cfg.pass), static_cast<std::size_t>(255));
    std::array<char, 3 + 255 + 255> auth{};
    auth[0] = 1;
    auth[1] = static_cast<char>(ul);
    if (ul) std::memcpy(auth.data() + 2, cfg.user, ul);
    auth[2 + ul] = static_cast<char>(pl);
    if (pl) std::memcpy(auth.data() + 3 + ul, cfg.pass, pl);
    if (!send_all_timeout(fd, auth.data(), 3 + ul + pl, deadline))
        return NetEngineError::NotProxy;
    std::array<char, 2> authReply{};
    if (!recv_exact_timeout(fd, authReply.data(), authReply.size(), deadline) ||
        static_cast<unsigned char>(authReply[1]) != 0)
        return NetEngineError::BadCredentials;
    return NetEngineError::Ok;
}

NetEngineError socks5_handshake(int fd, const NetConfig& cfg, const std::string& host,
                                std::uint16_t port, Deadline& deadline) {
    const NetEngineError authErr = socks5_authenticate(fd, cfg, deadline);
    if (authErr != NetEngineError::Ok) return authErr;

    std::array<char, 5 + 255 + 2> request{};
    std::size_t len = 0;
    request[len++] = 5;
    request[len++] = 1;
    request[len++] = 0;
    struct sockaddr_in v4{};
    if (::inet_pton(AF_INET, host.c_str(), &v4.sin_addr) == 1) {
        request[len++] = 1;
        std::memcpy(request.data() + len, &v4.sin_addr, 4);
        len += 4;
    } else {
        if (host.empty() || host.size() > 255) return NetEngineError::Request;
        request[len++] = 3;
        request[len++] = static_cast<char>(host.size());
        std::memcpy(request.data() + len, host.data(), host.size());
        len += host.size();
    }
    request[len++] = static_cast<char>(port >> 8);
    request[len++] = static_cast<char>(port & 0xff);
    if (!send_all_timeout(fd, request.data(), len, deadline))
        return NetEngineError::NotProxy;

    std::array<char, 4> reply{};
    if (!recv_exact_timeout(fd, reply.data(), reply.size(), deadline) ||
        static_cast<unsigned char>(reply[0]) != 5 ||
        static_cast<unsigned char>(reply[1]) != 0)
        return NetEngineError::Request;

    std::array<char, 300> tail{};
    const unsigned char atyp = static_cast<unsigned char>(reply[3]);
    if (atyp == 1) {
        if (!recv_exact_timeout(fd, tail.data(), 6, deadline)) return NetEngineError::Request;
    } else if (atyp == 3) {
        std::array<char, 1> lenByte{};
        if (!recv_exact_timeout(fd, lenByte.data(), 1, deadline)) return NetEngineError::Request;
        const std::size_t domainLen = static_cast<unsigned char>(lenByte[0]);
        if (!recv_exact_timeout(fd, tail.data(), domainLen + 2, deadline))
            return NetEngineError::Request;
    } else if (atyp == 4) {
        if (!recv_exact_timeout(fd, tail.data(), 18, deadline)) return NetEngineError::Request;
    } else {
        return NetEngineError::Request;
    }
    return NetEngineError::Ok;
}

NetEngineError http_connect_handshake(int fd, const NetConfig& cfg, const std::string& host,
                                      std::uint16_t port, Deadline& deadline) {
    std::string req = "CONNECT ";
    req += host;
    req.push_back(':');
    req += std::to_string(port);
    req += " HTTP/1.1\r\nHost: ";
    req += host;
    req.push_back(':');
    req += std::to_string(port);
    req += "\r\n";
    if (has_credentials(cfg)) req += tb::basic_auth_header(cfg.user, cfg.pass);
    req += "Proxy-Connection: keep-alive\r\n\r\n";
    if (!send_all_timeout(fd, req.data(), req.size(), deadline))
        return NetEngineError::NotProxy;

    std::array<char, 4096> response{};
    std::size_t responseLen = 0;
    if (!recv_headers_timeout(fd, response.data(), response.size(), &responseLen, deadline))
        return NetEngineError::NotProxy;
    const std::string_view headers(response.data(), responseLen);
    // Status line must begin with HTTP/1.x.
    if (headers.size() < 7 || std::memcmp(headers.data(), "HTTP/1.", 7) != 0)
        return NetEngineError::NotProxy;
    const int code = tb::http_status_code(headers);
    if (code == 407) return NetEngineError::BadCredentials;
    if (code < 200 || code >= 300) return NetEngineError::Request;
    return NetEngineError::Ok;
}

NetEngineError run_handshake(int fd, const NetConfig& cfg, const std::string& host,
                             std::uint16_t port, UpstreamProto proto, Deadline& deadline) {
    if (proto == UpstreamProto::HttpConnect)
        return http_connect_handshake(fd, cfg, host, port, deadline);
    return socks5_handshake(fd, cfg, host, port, deadline);
}

} // namespace

UpstreamResult connect_upstream_blocking(const NetConfig& cfg, const std::string& host,
                                         std::uint16_t port, int timeoutMs,
                                         UpstreamProto preferred) {
    UpstreamResult result;
    const UpstreamProto first = preferred == UpstreamProto::HttpConnect
                                    ? UpstreamProto::HttpConnect
                                    : UpstreamProto::Socks5;
    const UpstreamProto second = first == UpstreamProto::Socks5
                                     ? UpstreamProto::HttpConnect
                                     : UpstreamProto::Socks5;

    int fd = connect_tcp_timeout(cfg.ip, static_cast<std::uint16_t>(cfg.socksPort), timeoutMs);
    if (fd < 0) {
        result.err = NetEngineError::UpstreamUnreachable;
        return result;
    }

    NetEngineError err;
    {
        Deadline deadline(timeoutMs);
        err = run_handshake(fd, cfg, host, port, first, deadline);
    }
    if (err == NetEngineError::Ok) {
        make_plain_blocking(fd);
        result.fd = fd;
        result.proto = first;
        result.err = NetEngineError::Ok;
        return result;
    }

    // Only protocol mismatch justifies trying the other protocol: an auth
    // failure would be identical on both, and a TCP failure is independent.
    if (err == NetEngineError::NotProxy) {
        ::close(fd);
        fd = connect_tcp_timeout(cfg.ip, static_cast<std::uint16_t>(cfg.socksPort), timeoutMs);
        if (fd < 0) {
            result.err = NetEngineError::UpstreamUnreachable;
            return result;
        }
        Deadline deadline(timeoutMs);
        err = run_handshake(fd, cfg, host, port, second, deadline);
        if (err == NetEngineError::Ok) {
            make_plain_blocking(fd);
            result.fd = fd;
            result.proto = second;
            result.err = NetEngineError::Ok;
            return result;
        }
    }

    ::close(fd);
    result.err = err;
    return result;
}

int test_upstream(const NetConfig& cfg, UpstreamProto* detected, int timeoutMs) {
    if (detected) *detected = UpstreamProto::Socks5;

    const int fd = connect_tcp_timeout(cfg.ip, static_cast<std::uint16_t>(cfg.socksPort),
                                       timeoutMs);
    if (fd < 0) return 1;

    NetEngineError err;
    {
        Deadline deadline(timeoutMs);
        err = socks5_authenticate(fd, cfg, deadline);
    }
    if (err == NetEngineError::Ok) {
        ::close(fd);
        if (detected) *detected = UpstreamProto::Socks5;
        return 0;
    }
    if (err == NetEngineError::BadCredentials) {
        ::close(fd);
        return 3;
    }
    ::close(fd);

    const int hfd = connect_tcp_timeout(cfg.ip, static_cast<std::uint16_t>(cfg.socksPort),
                                        timeoutMs);
    if (hfd < 0) return 1;
    {
        Deadline deadline(timeoutMs);
        err = http_connect_handshake(hfd, cfg, "cp.cloudflare.com", 80, deadline);
    }
    ::close(hfd);
    if (err == NetEngineError::Ok) {
        if (detected) *detected = UpstreamProto::HttpConnect;
        return 0;
    }
    if (err == NetEngineError::BadCredentials) return 3;
    return 2;
}

} // namespace tb

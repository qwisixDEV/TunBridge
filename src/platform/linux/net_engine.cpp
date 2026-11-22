#include "tunbridge/net_engine.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <cctype>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif
#ifndef EPOLL_CLOEXEC
#define EPOLL_CLOEXEC O_CLOEXEC
#endif
#ifndef SOCK_CLOEXEC
#define SOCK_CLOEXEC O_CLOEXEC
#endif
#ifndef EFD_CLOEXEC
#define EFD_CLOEXEC O_CLOEXEC
#endif
#ifndef EFD_NONBLOCK
#define EFD_NONBLOCK O_NONBLOCK
#endif

namespace tb {
namespace {

constexpr std::size_t kHeaderCap = 16u * 1024u;
constexpr std::size_t kRelayCap = 32u * 1024u;
constexpr std::size_t kHandshakeCap = 2u * 1024u;
constexpr std::size_t kSlotCount = 512u;
constexpr std::size_t kMaxAcceptsPerEvent = 64u;
constexpr std::size_t npos = static_cast<std::size_t>(-1);

// SIGPIPE must be ignored exactly once for the whole process. send(MSG_NOSIGNAL)
// is used everywhere, but this is a cheap extra safety net.
void ignore_sigpipe() {
    static const bool installed = [] {
        struct sigaction sa{};
        sa.sa_handler = SIG_IGN;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = 0;
        return ::sigaction(SIGPIPE, &sa, nullptr) == 0;
    }();
    (void)installed;
}

bool set_nonblocking(int fd) {
    const int flags = ::fcntl(fd, F_GETFL, 0);
    if (flags < 0) return false;
    return ::fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

bool set_nodelay(int fd) {
    const int one = 1;
    return ::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)) == 0;
}

bool set_reuseaddr(int fd) {
    const int one = 1;
    return ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) == 0;
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

char lower_ascii(char c) {
    return static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
}

bool iequals(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    for (std::size_t i = 0; i < a.size(); ++i)
        if (lower_ascii(a[i]) != lower_ascii(b[i])) return false;
    return true;
}

bool istarts_with(std::string_view s, std::string_view prefix) {
    return s.size() >= prefix.size() && iequals(s.substr(0, prefix.size()), prefix);
}

std::string_view trim_view(std::string_view s) {
    const std::size_t first = s.find_first_not_of(" \t");
    if (first == npos) return {};
    const std::size_t last = s.find_last_not_of(" \t");
    return s.substr(first, last - first + 1);
}

std::size_t find_header_end(const char* data, std::size_t len) {
    for (std::size_t i = 0; i + 4 <= len; ++i) {
        if (data[i] == '\r' && data[i + 1] == '\n' &&
            data[i + 2] == '\r' && data[i + 3] == '\n')
            return i;
    }
    return npos;
}

// Prefer an IPv4 ATYP for named destinations; fall back to SOCKS5 domain form
// if the name cannot be resolved locally (the proxy can still resolve it).
bool resolve_ipv4(const std::string& host, struct in_addr& out) {
    if (::inet_pton(AF_INET, host.c_str(), &out) == 1) return true;
    if (host.empty() || host.find(':') != std::string::npos || host.size() > 255) return false;
    struct addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo* res = nullptr;
    if (::getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0 || !res) return false;
    if (!res->ai_addr || res->ai_addrlen < sizeof(struct sockaddr_in)) {
        ::freeaddrinfo(res);
        return false;
    }
    const auto* v4 = reinterpret_cast<const struct sockaddr_in*>(res->ai_addr);
    out = v4->sin_addr;
    ::freeaddrinfo(res);
    return true;
}

constexpr char kBadGateway[] = "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n";
constexpr char kBadRequest[] = "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n";
constexpr char kConnectOk[] = "HTTP/1.1 200 Connection Established\r\n\r\n";

struct Slot {
    enum class Phase : unsigned char {
        Free,
        ReadRequest,
        Connecting,
        SocksGreeting,
        SocksAuth,
        SocksConnect,
        HttpConnect,
        Active,
    };

    int client{-1};
    int up{-1};
    Phase phase{Phase::Free};
    std::size_t index{0};
    bool clientEof{false};
    bool upEof{false};
    bool closeAfterFlush{false};
    int attempt{0}; // 0 = SOCKS5 first, 1 = HTTP CONNECT fallback.
    bool isConnect{false};
    std::uint16_t port{0};
    std::string host;

    std::array<char, kHeaderCap> req{};
    std::size_t reqLen{0};
    std::size_t bodyOff{0}; // Bytes after \r\n\r\n inside req[].
    std::size_t bodyLen{0};

    std::array<char, kHeaderCap + 1024> reqOut{}; // Rewritten plain-HTTP headers.
    std::size_t reqOutLen{0};
    std::size_t reqOutOff{0};

    std::array<char, kHeaderCap> upHdr{}; // Handshake reply accumulator.
    std::size_t upHdrLen{0};
    std::array<char, kHandshakeCap> handTx{}; // Outgoing handshake bytes.
    std::size_t handTxLen{0};
    std::size_t handTxOff{0};

    std::array<char, kRelayCap> toUp{};
    std::size_t toUpLen{0};
    std::size_t toUpOff{0};
    std::array<char, kRelayCap> toClient{};
    std::size_t toClientLen{0};
    std::size_t toClientOff{0};
};

} // namespace

struct NetEngine::Impl {
    Impl(NetConfig c, NetStats* s) : cfg(std::move(c)), stats(s) {}

    NetConfig cfg;
    NetStats* stats{nullptr};

    int ep{-1};
    int listenFd{-1};
    int eventFd{-1};
    int boundPort{0};

    std::atomic<bool> running{false};
    std::atomic<bool> stopping{false};
    std::thread worker;
    std::mutex mu;
    std::condition_variable cv;
    bool ready{false};

    std::vector<std::unique_ptr<Slot>> slots;
    std::vector<std::size_t> freeList;
    std::unordered_map<int, std::size_t> fdMap;

    // ------------------------------------------------------------------
    // Setup / teardown
    // ------------------------------------------------------------------
    bool setup_listener(std::string* err) {
        ignore_sigpipe();

        ep = ::epoll_create1(EPOLL_CLOEXEC);
        if (ep < 0) {
            if (err) *err = "epoll_create1 failed";
            return false;
        }
        eventFd = ::eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
        if (eventFd < 0) {
            if (err) *err = "eventfd failed";
            ::close(ep);
            ep = -1;
            return false;
        }
        watch_fd(eventFd, true, EPOLLIN);

        const int preferred = cfg.localPort > 0 ? cfg.localPort : 8888;
        bool bound = false;
        for (int i = 0; i <= 32 && !bound; ++i) {
            int port = (i == 32) ? 0 : preferred + i;
            if (i < 32 && (port < 1025 || port > 65000))
                port = 10000 + (i % 5000);

            const int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
            if (fd < 0) continue;
            set_reuseaddr(fd);
            if (!set_nonblocking(fd)) {
                ::close(fd);
                continue;
            }
            struct sockaddr_in addr{};
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            addr.sin_port = htons(static_cast<std::uint16_t>(port));
            bool ok = ::bind(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) == 0 &&
                      ::listen(fd, SOMAXCONN) == 0;
            if (ok && port == 0) {
                socklen_t len = sizeof(addr);
                if (::getsockname(fd, reinterpret_cast<struct sockaddr*>(&addr), &len) == 0)
                    port = static_cast<int>(ntohs(addr.sin_port));
            }
            if (ok && port > 0) {
                listenFd = fd;
                boundPort = port;
                bound = true;
            } else {
                ::close(fd);
            }
        }
        if (!bound) {
            if (err) *err = "cannot bind local port on loopback";
            if (eventFd >= 0) {
                ::close(eventFd);
                eventFd = -1;
            }
            if (ep >= 0) {
                ::close(ep);
                ep = -1;
            }
            return false;
        }
        watch_fd(listenFd, true, EPOLLIN | EPOLLERR | EPOLLHUP);

        slots.reserve(kSlotCount);
        freeList.reserve(kSlotCount);
        for (std::size_t i = 0; i < kSlotCount; ++i) {
            slots.push_back(std::make_unique<Slot>());
            slots.back()->index = i;
            freeList.push_back(i);
        }
        return true;
    }

    void cleanup_all() {
        for (auto& slot : slots) {
            if (!slot) continue;
            close_field(slot->client);
            close_field(slot->up);
        }
        fdMap.clear();
        if (listenFd >= 0) {
            ::close(listenFd);
            listenFd = -1;
        }
        if (eventFd >= 0) {
            ::close(eventFd);
            eventFd = -1;
        }
        if (ep >= 0) {
            ::close(ep);
            ep = -1;
        }
    }

    // ------------------------------------------------------------------
    // fd / epoll helpers
    // ------------------------------------------------------------------
    void watch_fd(int fd, bool add, std::uint32_t events) {
        if (fd < 0 || ep < 0) return;
        struct epoll_event ev{};
        ev.events = events;
        ev.data.fd = fd;
        if (add) {
            ::epoll_ctl(ep, EPOLL_CTL_ADD, fd, &ev);
            return;
        }
        if (::epoll_ctl(ep, EPOLL_CTL_MOD, fd, &ev) < 0 && errno == ENOENT)
            ::epoll_ctl(ep, EPOLL_CTL_ADD, fd, &ev);
    }

    void close_field(int& fd) {
        if (fd < 0) return;
        if (ep >= 0) ::epoll_ctl(ep, EPOLL_CTL_DEL, fd, nullptr);
        ::close(fd);
        fdMap.erase(fd);
        fd = -1;
    }

    void update_watch(Slot& s) {
        if (s.phase == Slot::Phase::Free) return;
        if (s.client >= 0) {
            std::uint32_t events = EPOLLERR | EPOLLHUP;
            if (s.phase == Slot::Phase::ReadRequest) {
                events |= EPOLLIN;
            } else if (s.phase == Slot::Phase::Active) {
                if (!s.closeAfterFlush && !s.clientEof &&
                    s.toUpLen == s.toUpOff && s.reqOutLen == s.reqOutOff)
                    events |= EPOLLIN;
                if (s.toClientOff < s.toClientLen) events |= EPOLLOUT;
            }
            watch_fd(s.client, false, events);
        }
        if (s.up >= 0) {
            std::uint32_t events = EPOLLERR | EPOLLHUP;
            switch (s.phase) {
            case Slot::Phase::Connecting:
                events |= EPOLLOUT;
                break;
            case Slot::Phase::SocksGreeting:
            case Slot::Phase::SocksAuth:
            case Slot::Phase::SocksConnect:
            case Slot::Phase::HttpConnect:
                events |= EPOLLIN;
                if (s.handTxOff < s.handTxLen) events |= EPOLLOUT;
                break;
            case Slot::Phase::Active:
                if (!s.upEof && s.toClientLen == s.toClientOff) events |= EPOLLIN;
                if (s.reqOutOff < s.reqOutLen || s.toUpOff < s.toUpLen) events |= EPOLLOUT;
                break;
            default:
                break;
            }
            watch_fd(s.up, false, events);
        }
    }

    Slot& reset_slot(std::size_t index) {
        Slot& s = *slots[index];
        s = Slot{};
        s.index = index;
        return s;
    }

    void release(Slot& s) {
        const std::size_t index = s.index;
        close_field(s.client);
        close_field(s.up);
        if (stats) stats->connections.fetch_sub(1, std::memory_order_relaxed);
        s = Slot{};
        s.index = index;
        s.phase = Slot::Phase::Free;
        freeList.push_back(index);
    }

    void note_rx(std::size_t n) {
        if (stats && n) stats->rx.fetch_add(static_cast<std::uint64_t>(n), std::memory_order_relaxed);
    }
    void note_tx(std::size_t n) {
        if (stats && n) stats->tx.fetch_add(static_cast<std::uint64_t>(n), std::memory_order_relaxed);
    }

    // ------------------------------------------------------------------
    // Main loop
    // ------------------------------------------------------------------
    void run() {
        running.store(true, std::memory_order_release);
        {
            std::lock_guard<std::mutex> lock(mu);
            ready = true;
        }
        cv.notify_all();

        std::array<struct epoll_event, 64> events{};
        while (!stopping.load(std::memory_order_acquire)) {
            const int n = ::epoll_wait(ep, events.data(), static_cast<int>(events.size()), -1);
            if (n < 0) {
                if (errno == EINTR) continue;
                break;
            }
            for (int i = 0; i < n; ++i) handle_event(events[i]);
        }
        running.store(false, std::memory_order_release);
        cleanup_all();
    }

    void handle_event(const struct epoll_event& ev) {
        const int fd = ev.data.fd;
        if (fd == eventFd) {
            std::uint64_t token = 0;
            while (::read(eventFd, &token, sizeof(token)) > 0) { /* drain */ }
            return;
        }
        if (fd == listenFd) {
            accept_clients();
            return;
        }
        const auto it = fdMap.find(fd);
        if (it == fdMap.end()) return;
        Slot& s = *slots[it->second];
        if (fd == s.client) {
            on_client(s, ev.events);
        } else if (fd == s.up) {
            on_upstream(s, ev.events);
        }
    }

    void accept_clients() {
        for (std::size_t i = 0; i < kMaxAcceptsPerEvent; ++i) {
            const int fd = ::accept(listenFd, nullptr, nullptr);
            if (fd < 0) {
                if (errno == EINTR) continue;
                break; // EAGAIN: no more pending clients, never poll.
            }
            if (freeList.empty() || !set_nonblocking(fd) || !set_nodelay(fd)) {
                ::close(fd);
                continue;
            }
            const std::size_t index = freeList.back();
            freeList.pop_back();
            Slot& s = reset_slot(index);
            s.client = fd;
            s.phase = Slot::Phase::ReadRequest;
            fdMap[fd] = index;
            watch_fd(fd, true, EPOLLIN | EPOLLERR | EPOLLHUP);
            if (stats) stats->connections.fetch_add(1, std::memory_order_relaxed);
        }
    }

    // ------------------------------------------------------------------
    // Client side
    // ------------------------------------------------------------------
    void on_client(Slot& s, std::uint32_t events) {
        if (s.phase == Slot::Phase::ReadRequest) {
            read_request(s);
            return;
        }
        if (s.phase != Slot::Phase::Active) return;

        if (s.toClientOff < s.toClientLen) flush_to_client(s);
        if (s.phase == Slot::Phase::Free) return;

        if ((events & EPOLLIN) && !s.closeAfterFlush && !s.clientEof &&
            s.toUpLen == s.toUpOff && s.reqOutLen == s.reqOutOff) {
            read_client_data(s);
            if (s.phase == Slot::Phase::Free) return;
        }
        finish_if_done(s);
        update_watch(s);
    }

    void read_request(Slot& s) {
        while (s.reqLen < s.req.size()) {
            const ssize_t n = ::recv(s.client, s.req.data() + s.reqLen, s.req.size() - s.reqLen, 0);
            if (n > 0) {
                s.reqLen += static_cast<std::size_t>(n);
                if (find_header_end(s.req.data(), s.reqLen) != npos) {
                    parse_request(s);
                    return;
                }
                continue;
            }
            if (n == 0) {
                release(s);
                return;
            }
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
            release(s);
            return;
        }
        // Fixed header buffer exhausted without a complete header block.
        respond_and_close(s, kBadRequest);
    }

    void parse_request(Slot& s) {
        const std::string_view all(s.req.data(), s.reqLen);
        const std::size_t headerEnd = find_header_end(s.req.data(), s.reqLen);
        const std::size_t firstEnd = all.find("\r\n");
        if (headerEnd == npos || firstEnd == npos || firstEnd == 0) {
            respond_and_close(s, kBadRequest);
            return;
        }

        const std::string_view first = all.substr(0, firstEnd);
        const std::size_t sp1 = first.find(' ');
        if (sp1 == npos || sp1 == 0) {
            respond_and_close(s, kBadRequest);
            return;
        }
        const std::size_t sp2 = first.find(' ', sp1 + 1);
        const std::string_view method = first.substr(0, sp1);
        const std::string_view uri = sp2 == npos ? first.substr(sp1 + 1)
                                                 : first.substr(sp1 + 1, sp2 - sp1 - 1);
        std::string_view version = sp2 == npos ? std::string_view("HTTP/1.1")
                                               : trim_view(first.substr(sp2 + 1));
        if (version.empty()) version = "HTTP/1.1";

        s.isConnect = iequals(method, "CONNECT");
        std::string_view path = uri;
        std::string authority;

        if (s.isConnect) {
            if (!tb::parse_host_port(uri, s.host, s.port, 443) || s.host.empty() ||
                s.host.size() > 255) {
                respond_and_close(s, kBadRequest);
                return;
            }
        } else if (istarts_with(uri, "http://")) {
            const std::string_view rest = uri.substr(7);
            const std::size_t slash = rest.find('/');
            authority = std::string(slash == npos ? rest : rest.substr(0, slash));
            path = slash == npos ? std::string_view("/") : rest.substr(slash);
            if (!tb::parse_host_port(authority, s.host, s.port, 80) || s.host.empty() ||
                s.host.size() > 255) {
                respond_and_close(s, kBadRequest);
                return;
            }
        } else {
            const std::string_view headers = all.substr(firstEnd + 2, headerEnd - firstEnd - 2);
            std::size_t pos = 0;
            while (pos < headers.size()) {
                const std::size_t nl = headers.find("\r\n", pos);
                if (nl == npos) break;
                const std::string_view line = headers.substr(pos, nl - pos);
                if (istarts_with(line, "Host:")) {
                    authority = std::string(trim_view(line.substr(5)));
                    break;
                }
                pos = nl + 2;
            }
            if (authority.empty()) {
                respond_and_close(s, kBadRequest);
                return;
            }
            if (!tb::parse_host_port(authority, s.host, s.port, 80) || s.host.empty() ||
                s.host.size() > 255) {
                respond_and_close(s, kBadRequest);
                return;
            }
        }

        if (!s.isConnect) {
            std::string out;
            out.reserve(headerEnd + 128);
            out.append(method);
            out.push_back(' ');
            out.append(path);
            out.push_back(' ');
            out.append(version);
            out.append("\r\n");
            const std::string_view headers = all.substr(firstEnd + 2, headerEnd - firstEnd - 2);
            std::size_t pos = 0;
            while (pos < headers.size()) {
                const std::size_t nl = headers.find("\r\n", pos);
                if (nl == npos) break;
                const std::string_view line = headers.substr(pos, nl - pos);
                pos = nl + 2;
                if (istarts_with(line, "Connection:") ||
                    istarts_with(line, "Proxy-Connection:") ||
                    istarts_with(line, "Proxy-Authorization:") ||
                    istarts_with(line, "Keep-Alive:"))
                    continue;
                out.append(line);
                out.append("\r\n");
            }
            out.append("Connection: close\r\n\r\n");
            if (out.size() > s.reqOut.size()) {
                respond_and_close(s, kBadRequest);
                return;
            }
            std::memcpy(s.reqOut.data(), out.data(), out.size());
            s.reqOutLen = out.size();
            s.reqOutOff = 0;
        }

        s.bodyOff = headerEnd + 4;
        s.bodyLen = s.reqLen - s.bodyOff;
        begin_connect(s, 0);
    }

    void read_client_data(Slot& s) {
        for (;;) {
            const ssize_t n = ::recv(s.client, s.toUp.data(), s.toUp.size(), 0);
            if (n > 0) {
                s.toUpLen = static_cast<std::size_t>(n);
                s.toUpOff = 0;
                note_tx(s.toUpLen);
                flush_to_up(s);
                return;
            }
            if (n == 0) {
                s.clientEof = true;
                if (s.up >= 0) ::shutdown(s.up, SHUT_WR);
                return;
            }
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
            release(s);
            return;
        }
    }

    void flush_to_client(Slot& s) {
        while (s.toClientOff < s.toClientLen) {
            const ssize_t n = ::send(s.client, s.toClient.data() + s.toClientOff,
                                     s.toClientLen - s.toClientOff, MSG_NOSIGNAL);
            if (n > 0) {
                s.toClientOff += static_cast<std::size_t>(n);
                continue;
            }
            if (n < 0 && errno == EINTR) continue;
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
            release(s);
            return;
        }
        s.toClientLen = 0;
        s.toClientOff = 0;
    }

    void flush_to_up(Slot& s) {
        while (s.reqOutOff < s.reqOutLen) {
            const ssize_t n = ::send(s.up, s.reqOut.data() + s.reqOutOff,
                                     s.reqOutLen - s.reqOutOff, MSG_NOSIGNAL);
            if (n > 0) {
                s.reqOutOff += static_cast<std::size_t>(n);
                continue;
            }
            if (n < 0 && errno == EINTR) continue;
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
            release(s);
            return;
        }
        s.reqOutLen = 0;
        s.reqOutOff = 0;

        while (s.toUpOff < s.toUpLen) {
            const ssize_t n = ::send(s.up, s.toUp.data() + s.toUpOff,
                                     s.toUpLen - s.toUpOff, MSG_NOSIGNAL);
            if (n > 0) {
                s.toUpOff += static_cast<std::size_t>(n);
                continue;
            }
            if (n < 0 && errno == EINTR) continue;
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
            release(s);
            return;
        }
        s.toUpLen = 0;
        s.toUpOff = 0;
    }

    // ------------------------------------------------------------------
    // Upstream connect / handshake (all asynchronous)
    // ------------------------------------------------------------------
    void begin_connect(Slot& s, int attempt) {
        s.attempt = attempt;
        s.upHdrLen = 0;
        s.handTxLen = 0;
        s.handTxOff = 0;

        sockaddr_storage addr{};
        socklen_t addrLen = 0;
        if (!resolve_peer(cfg.ip, static_cast<std::uint16_t>(cfg.socksPort), addr, addrLen)) {
            respond_and_close(s, kBadGateway);
            return;
        }
        const int fd = ::socket(addr.ss_family, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (fd < 0 || !set_nonblocking(fd) || !set_nodelay(fd)) {
            if (fd >= 0) ::close(fd);
            respond_and_close(s, kBadGateway);
            return;
        }
        s.up = fd;
        fdMap[fd] = s.index;
        watch_fd(fd, true, EPOLLOUT | EPOLLERR | EPOLLHUP);
        s.phase = Slot::Phase::Connecting;

        const int rc = ::connect(fd, reinterpret_cast<struct sockaddr*>(&addr), addrLen);
        if (rc == 0) {
            finish_connect(s);
            return;
        }
        if (errno == EINPROGRESS || errno == EALREADY) {
            update_watch(s);
            return;
        }
        // A refused/timed-out TCP connect is not a handshake failure: no proto fallback.
        respond_and_close(s, kBadGateway);
    }

    void finish_connect(Slot& s) {
        int soError = 0;
        socklen_t len = static_cast<socklen_t>(sizeof(soError));
        if (s.up < 0 || ::getsockopt(s.up, SOL_SOCKET, SO_ERROR, &soError, &len) < 0 ||
            soError != 0) {
            respond_and_close(s, kBadGateway);
            return;
        }
        s.upHdrLen = 0;
        if (s.attempt == 0) {
            build_greeting(s);
            s.phase = Slot::Phase::SocksGreeting;
        } else {
            if (!build_http_request(s)) {
                respond_and_close(s, kBadGateway);
                return;
            }
            s.phase = Slot::Phase::HttpConnect;
        }
        flush_handshake(s);
        update_watch(s);
    }

    bool has_credentials() const {
        return cfg.user[0] != '\0' || cfg.pass[0] != '\0';
    }

    void build_greeting(Slot& s) {
        if (has_credentials()) {
            const unsigned char greeting[4] = {5, 2, 0, 2};
            std::memcpy(s.handTx.data(), greeting, sizeof(greeting));
            s.handTxLen = sizeof(greeting);
        } else {
            const unsigned char greeting[3] = {5, 1, 0};
            std::memcpy(s.handTx.data(), greeting, sizeof(greeting));
            s.handTxLen = sizeof(greeting);
        }
        s.handTxOff = 0;
    }

    void build_auth(Slot& s) {
        const std::size_t ul = std::min(std::strlen(cfg.user), static_cast<std::size_t>(255));
        const std::size_t pl = std::min(std::strlen(cfg.pass), static_cast<std::size_t>(255));
        s.handTx[0] = 1;
        s.handTx[1] = static_cast<char>(ul);
        if (ul) std::memcpy(s.handTx.data() + 2, cfg.user, ul);
        s.handTx[2 + ul] = static_cast<char>(pl);
        if (pl) std::memcpy(s.handTx.data() + 3 + ul, cfg.pass, pl);
        s.handTxLen = 3 + ul + pl;
        s.handTxOff = 0;
    }

    void build_socks_connect(Slot& s) {
        struct in_addr v4{};
        std::size_t pos = 0;
        s.handTx[pos++] = 5;
        s.handTx[pos++] = 1;
        s.handTx[pos++] = 0;
        if (resolve_ipv4(s.host, v4)) {
            s.handTx[pos++] = 1;
            std::memcpy(s.handTx.data() + pos, &v4, 4);
            pos += 4;
        } else {
            s.handTx[pos++] = 3;
            s.handTx[pos++] = static_cast<char>(s.host.size());
            std::memcpy(s.handTx.data() + pos, s.host.data(), s.host.size());
            pos += s.host.size();
        }
        s.handTx[pos++] = static_cast<char>(s.port >> 8);
        s.handTx[pos++] = static_cast<char>(s.port & 0xff);
        s.handTxLen = pos;
        s.handTxOff = 0;
    }

    bool build_http_request(Slot& s) {
        std::string req = "CONNECT ";
        req += s.host;
        req.push_back(':');
        req += std::to_string(s.port);
        req += " HTTP/1.1\r\nHost: ";
        req += s.host;
        req.push_back(':');
        req += std::to_string(s.port);
        req += "\r\n";
        if (has_credentials())
            req += tb::basic_auth_header(cfg.user, cfg.pass);
        req += "Proxy-Connection: keep-alive\r\n\r\n";
        if (req.size() > s.handTx.size()) return false;
        std::memcpy(s.handTx.data(), req.data(), req.size());
        s.handTxLen = req.size();
        s.handTxOff = 0;
        return true;
    }

    void flush_handshake(Slot& s) {
        while (s.handTxOff < s.handTxLen) {
            const ssize_t n = ::send(s.up, s.handTx.data() + s.handTxOff,
                                     s.handTxLen - s.handTxOff, MSG_NOSIGNAL);
            if (n > 0) {
                s.handTxOff += static_cast<std::size_t>(n);
                continue;
            }
            if (n < 0 && errno == EINTR) continue;
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
            handshake_failed(s);
            return;
        }
        s.handTxLen = 0;
        s.handTxOff = 0;
    }

    void handshake_failed(Slot& s) {
        if (s.up >= 0) close_field(s.up);
        // AUTO: a failed handshake is retried with the other proxy protocol.
        if (s.attempt == 0) {
            begin_connect(s, 1);
        } else {
            respond_and_close(s, kBadGateway);
        }
    }

    void on_upstream(Slot& s, std::uint32_t events) {
        switch (s.phase) {
        case Slot::Phase::Connecting:
            finish_connect(s);
            update_watch(s);
            return;
        case Slot::Phase::SocksGreeting:
        case Slot::Phase::SocksAuth:
        case Slot::Phase::SocksConnect:
        case Slot::Phase::HttpConnect: {
            if ((events & EPOLLOUT) && s.handTxOff < s.handTxLen) {
                flush_handshake(s);
                if (s.phase == Slot::Phase::Free || s.phase == Slot::Phase::Connecting) {
                    update_watch(s);
                    return;
                }
            }
            read_handshake(s);
            update_watch(s);
            return;
        }
        case Slot::Phase::Active:
            if (s.reqOutOff < s.reqOutLen || s.toUpOff < s.toUpLen) flush_to_up(s);
            if (s.phase == Slot::Phase::Free) return;
            if ((events & EPOLLIN) && !s.upEof && s.toClientLen == s.toClientOff)
                read_upstream_data(s);
            if (s.phase == Slot::Phase::Free) return;
            finish_if_done(s);
            update_watch(s);
            return;
        default:
            return;
        }
    }

    void read_handshake(Slot& s) {
        // Reads just enough bytes for the current handshake step. Leftover bytes
        // stay in upHdr[] and are parsed by the next step.
        auto ensure = [&](std::size_t need) -> bool {
            while (s.upHdrLen < need) {
                if (s.upHdrLen >= s.upHdr.size()) {
                    handshake_failed(s);
                    return false;
                }
                const ssize_t n = ::recv(s.up, s.upHdr.data() + s.upHdrLen,
                                         s.upHdr.size() - s.upHdrLen, 0);
                if (n > 0) {
                    s.upHdrLen += static_cast<std::size_t>(n);
                    continue;
                }
                if (n == 0) {
                    handshake_failed(s);
                    return false;
                }
                if (errno == EINTR) continue;
                if (errno == EAGAIN || errno == EWOULDBLOCK) return false;
                handshake_failed(s);
                return false;
            }
            return true;
        };

        for (;;) {
            if (s.phase == Slot::Phase::SocksGreeting) {
                if (!ensure(2)) return;
                const unsigned char ver = static_cast<unsigned char>(s.upHdr[0]);
                const unsigned char method = static_cast<unsigned char>(s.upHdr[1]);
                if (ver != 5) {
                    handshake_failed(s);
                    return;
                }
                s.upHdrLen = 0;
                if (method == 2) {
                    if (!has_credentials()) {
                        handshake_failed(s);
                        return;
                    }
                    build_auth(s);
                    s.phase = Slot::Phase::SocksAuth;
                    continue;
                }
                if (method != 0) {
                    handshake_failed(s);
                    return;
                }
                build_socks_connect(s);
                s.phase = Slot::Phase::SocksConnect;
                continue;
            }

            if (s.phase == Slot::Phase::SocksAuth) {
                if (!ensure(2)) return;
                if (static_cast<unsigned char>(s.upHdr[1]) != 0) {
                    handshake_failed(s);
                    return;
                }
                s.upHdrLen = 0;
                build_socks_connect(s);
                s.phase = Slot::Phase::SocksConnect;
                continue;
            }

            if (s.phase == Slot::Phase::SocksConnect) {
                if (!ensure(4)) return;
                if (static_cast<unsigned char>(s.upHdr[0]) != 5 ||
                    static_cast<unsigned char>(s.upHdr[1]) != 0) {
                    handshake_failed(s);
                    return;
                }
                const unsigned char atyp = static_cast<unsigned char>(s.upHdr[3]);
                std::size_t need = 0;
                if (atyp == 1) {
                    need = 10; // VER REP RSV ATYP IP(4) PORT(2)
                } else if (atyp == 4) {
                    need = 22; // VER REP RSV ATYP IP(16) PORT(2)
                } else if (atyp == 3) {
                    if (!ensure(5)) return;
                    need = 5u + static_cast<std::size_t>(static_cast<unsigned char>(s.upHdr[4])) + 2u;
                } else {
                    handshake_failed(s);
                    return;
                }
                if (!ensure(need)) return;
                activate(s, need, s.isConnect);
                return;
            }

            if (s.phase == Slot::Phase::HttpConnect) {
                std::size_t end = find_header_end(s.upHdr.data(), s.upHdrLen);
                while (end == npos && s.upHdrLen < s.upHdr.size()) {
                    const ssize_t n = ::recv(s.up, s.upHdr.data() + s.upHdrLen,
                                             s.upHdr.size() - s.upHdrLen, 0);
                    if (n > 0) {
                        s.upHdrLen += static_cast<std::size_t>(n);
                        end = find_header_end(s.upHdr.data(), s.upHdrLen);
                        continue;
                    }
                    if (n == 0) {
                        handshake_failed(s);
                        return;
                    }
                    if (errno == EINTR) continue;
                    if (errno == EAGAIN || errno == EWOULDBLOCK) return;
                    handshake_failed(s);
                    return;
                }
                if (end == npos) {
                    handshake_failed(s);
                    return;
                }
                const int code = tb::http_status_code(
                    std::string_view(s.upHdr.data(), end + 4));
                // 407 is a credential error; from the local client's point of
                // view any non-2xx reply simply means the tunnel is unavailable.
                (void)code;
                if (code < 200 || code >= 300) {
                    handshake_failed(s);
                    return;
                }
                activate(s, end + 4, s.isConnect);
                return;
            }
            return; // Any other phase is not a handshake phase.
        }
    }

    void activate(Slot& s, std::size_t consumed, bool sendConnectOk) {
        if (sendConnectOk) {
            const std::size_t len = sizeof(kConnectOk) - 1;
            std::memcpy(s.toClient.data(), kConnectOk, len);
            s.toClientLen = len;
            s.toClientOff = 0;
        }
        if (consumed < s.upHdrLen) {
            const std::size_t extra = s.upHdrLen - consumed;
            const std::size_t room = s.toClient.size() - s.toClientLen;
            const std::size_t take = std::min(extra, room);
            if (take) {
                std::memcpy(s.toClient.data() + s.toClientLen, s.upHdr.data() + consumed, take);
                s.toClientLen += take;
                note_rx(take);
            }
        }
        s.upHdrLen = 0;

        if (s.bodyLen > 0) {
            const std::size_t take = std::min(s.bodyLen, s.toUp.size());
            std::memcpy(s.toUp.data(), s.req.data() + s.bodyOff, take);
            s.toUpLen = take;
            s.toUpOff = 0;
            note_tx(take);
        }
        s.phase = Slot::Phase::Active;
        flush_to_client(s);
        if (s.phase == Slot::Phase::Free) return;
        flush_to_up(s);
        if (s.phase == Slot::Phase::Free) return;
        finish_if_done(s);
        update_watch(s);
    }

    void read_upstream_data(Slot& s) {
        for (;;) {
            const ssize_t n = ::recv(s.up, s.toClient.data(), s.toClient.size(), 0);
            if (n > 0) {
                s.toClientLen = static_cast<std::size_t>(n);
                s.toClientOff = 0;
                note_rx(s.toClientLen);
                flush_to_client(s);
                return;
            }
            if (n == 0) {
                s.upEof = true;
                ::shutdown(s.client, SHUT_WR);
                return;
            }
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
            release(s);
            return;
        }
    }

    void respond_and_close(Slot& s, const char* response) {
        close_field(s.up);
        const std::size_t len = std::strlen(response);
        std::memcpy(s.toClient.data(), response, len);
        s.toClientLen = len;
        s.toClientOff = 0;
        s.reqOutLen = 0;
        s.reqOutOff = 0;
        s.toUpLen = 0;
        s.toUpOff = 0;
        s.upHdrLen = 0;
        s.closeAfterFlush = true;
        s.phase = Slot::Phase::Active;
        flush_to_client(s);
        if (s.phase == Slot::Phase::Free) return;
        finish_if_done(s);
        update_watch(s);
    }

    void finish_if_done(Slot& s) {
        if (s.phase != Slot::Phase::Active) return;
        const bool drained = s.toClientOff >= s.toClientLen &&
                             s.toUpOff >= s.toUpLen &&
                             s.reqOutOff >= s.reqOutLen;
        if (s.closeAfterFlush) {
            if (drained) release(s);
            return;
        }
        if (s.clientEof && s.upEof && drained) release(s);
    }
};

NetEngine::NetEngine(NetConfig cfg, NetStats* stats)
    : impl_(std::make_unique<Impl>(std::move(cfg), stats)) {}

NetEngine::~NetEngine() {
    stop();
}

bool NetEngine::start(int* boundPort, std::string* err) {
    if (!impl_) {
        if (err) *err = "engine not initialized";
        return false;
    }
    if (impl_->running.load(std::memory_order_acquire) ||
        impl_->stopping.load(std::memory_order_acquire)) {
        if (err) *err = "engine already started or stopped";
        return false;
    }
    std::string localErr;
    if (!impl_->setup_listener(&localErr)) {
        if (err) *err = localErr;
        return false;
    }
    impl_->worker = std::thread([this] { impl_->run(); });
    std::unique_lock<std::mutex> lock(impl_->mu);
    impl_->cv.wait(lock, [this] { return impl_->ready; });
    const bool ok = impl_->running.load(std::memory_order_acquire);
    if (!ok) {
        if (err) *err = "epoll thread failed to start";
        return false;
    }
    if (boundPort) *boundPort = impl_->boundPort;
    return true;
}

void NetEngine::stop() {
    if (!impl_) return;
    impl_->stopping.store(true, std::memory_order_release);
    if (impl_->eventFd >= 0) {
        const std::uint64_t token = 1;
        while (::write(impl_->eventFd, &token, sizeof(token)) < 0 && errno == EINTR) { }
    }
    if (impl_->worker.joinable()) impl_->worker.join();
}

int NetEngine::port() const {
    return impl_ ? impl_->boundPort : 0;
}

bool NetEngine::running() const {
    return impl_ && impl_->running.load(std::memory_order_acquire) &&
           !impl_->stopping.load(std::memory_order_acquire);
}

} // namespace tb

// Linux LAN proxy scanner.
//
// Mirrors the behaviour of the original Win32 scanner without creating a
// thread per host: interfaces are discovered with getifaddrs(), candidates
// are ordered by priority, and connectivity is checked with batched
// non-blocking connect() + poll() (at most kBatchSize sockets in flight).
//
// Only standard C++20 + POSIX are used.

#include "tunbridge/scanner.hpp"

#include "tunbridge/core.hpp"
#include "tunbridge/xdg.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <map>
#include <string>
#include <vector>

#ifndef SOCK_CLOEXEC
#define SOCK_CLOEXEC 0
#endif

namespace tb {

namespace {

constexpr std::size_t kBatchSize = 64;
constexpr int kBatchPollMs = 900;
constexpr int kCancelSliceMs = 100;
constexpr std::size_t kMaxCandidates = 1024;
constexpr std::size_t kMaxPerSubnet = 384;

using Clock = std::chrono::steady_clock;

bool cancelled(const std::atomic<bool>* cancel) {
    return cancel != nullptr && cancel->load(std::memory_order_acquire);
}

int elapsed_ms(Clock::time_point start) {
    return static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(
        Clock::now() - start).count());
}

std::uint32_t ip_to_u32(const std::string& s) {
    struct in_addr a{};
    if (::inet_pton(AF_INET, s.c_str(), &a) != 1) return 0;
    return static_cast<std::uint32_t>(::ntohl(a.s_addr));
}

std::string u32_to_ip(std::uint32_t v) {
    struct in_addr a{};
    a.s_addr = ::htonl(v);
    char buf[INET_ADDRSTRLEN]{};
    if (!::inet_ntop(AF_INET, &a, buf, sizeof(buf))) return {};
    return std::string(buf);
}

std::string lower_copy(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

std::string trim_copy(std::string_view v) {
    const auto first = v.find_first_not_of(" \t\r\n");
    if (first == std::string_view::npos) return {};
    const auto last = v.find_last_not_of(" \t\r\n");
    return std::string(v.substr(first, last - first + 1));
}

// IP of the currently configured proxy, read back from the INI config.
std::string configured_proxy_ip() {
    std::map<std::string, std::string> kv;
    if (!tb::ini_load(tb::config_path(), kv)) return {};
    const auto it = kv.find("ip");
    if (it == kv.end()) return {};
    std::string v = it->second;
    const auto colon = v.find(':'); // UI may store "ip:port"
    if (colon != std::string::npos) v.resize(colon);
    v = trim_copy(v);
    return tb::is_safe_host(v) ? v : std::string{};
}

// Default gateway from /proc/net/route (destination 00000000).
std::uint32_t default_gateway() {
    std::ifstream f("/proc/net/route");
    if (!f) return 0;
    std::string line;
    std::getline(f, line); // header
    while (std::getline(f, line)) {
        char iface[64]{}, dst[64]{}, gw[64]{};
        if (std::sscanf(line.c_str(), "%63s %63s %63s", iface, dst, gw) != 3) continue;
        if (std::strcmp(dst, "00000000") != 0) continue;
        const std::uint32_t raw = static_cast<std::uint32_t>(std::strtoul(gw, nullptr, 16));
        if (raw == 0) continue;
#if defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__) && \
    __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
        return raw;
#else
        // /proc prints the in-memory little endian representation.
        return (raw >> 24) | ((raw >> 8) & 0x0000FF00u) |
               ((raw << 8) & 0x00FF0000u) | (raw << 24);
#endif
    }
    return 0;
}

struct Candidate {
    std::uint32_t ip{0};
    int group{9};
    std::size_t order{0};
};

bool skip_interface(const std::string& name) {
    const std::string l = lower_copy(name);
    if (l.rfind("tunbridge", 0) == 0) return true;
    return l.find("cloudflare") != std::string::npos;
}

void append_subnet_hosts(std::uint32_t net, std::uint32_t mask, int group,
                         std::vector<Candidate>& out) {
    const std::uint32_t base = net & mask;
    const std::uint32_t bcast = net | (~mask);
    if (base == 0 || bcast <= base + 1) return; // /0, /31, /32, error

    // Exclude unusable / synthetic ranges.
    if ((base & 0xFF000000u) == 0x7F000000u) return;             // loopback
    if ((base & 0xFF000000u) == 0x00000000u) return;             // 0.0.0.0/8
    if ((base & 0xF0000000u) == 0xE0000000u) return;             // multicast
    if ((base & 0xFFFF0000u) == 0xA9FE0000u) return;             // 169.254/16
    if ((base & 0xFFFFFF00u) == ip_to_u32("10.251.251.0")) return; // excluded

    std::vector<std::uint32_t> hosts;
    hosts.reserve(kMaxPerSubnet);

    // Hotspot gateways almost always end in .1 - visit those first,
    // including every /24 inside a larger aggregate route.
    for (std::uint64_t b = base; b <= bcast; b += 256) {
        const std::uint32_t h = static_cast<std::uint32_t>((b & 0xFFFFFF00u) | 1u);
        if (h > base && h < bcast) hosts.push_back(h);
        if (hosts.size() >= kMaxPerSubnet) break;
    }

    // Then spread samples across the rest of the range so a /16 does not
    // starve later subnets.
    const std::uint64_t count = static_cast<std::uint64_t>(bcast) - base + 1;
    const std::size_t remaining = kMaxPerSubnet > hosts.size()
                                      ? kMaxPerSubnet - hosts.size() : 0;
    if (remaining > 0 && count > 2) {
        for (std::size_t i = 0; i < remaining; ++i) {
            std::uint64_t idx = 1 + (static_cast<std::uint64_t>(i) * (count - 2)) / remaining;
            if (idx >= count - 1) idx = count - 2;
            const std::uint32_t h = base + static_cast<std::uint32_t>(idx);
            if (std::find(hosts.begin(), hosts.end(), h) == hosts.end()) hosts.push_back(h);
        }
    }

    for (std::size_t i = 0; i < hosts.size(); ++i)
        out.push_back({hosts[i], group, i});
}

std::vector<Candidate> build_candidates() {
    std::vector<Candidate> out;

    // Priority 0: last configured proxy IP (if it answers the probe).
    const std::string cfgIp = configured_proxy_ip();
    const std::uint32_t cfg = ip_to_u32(cfgIp);
    if (cfg != 0) out.push_back({cfg, 0, 0});

    // Priority 1: current default gateway.
    const std::uint32_t gw = default_gateway();
    if (gw != 0 &&
        (gw & 0xFFFFFF00u) != ip_to_u32("10.251.251.0") &&
        (gw & 0xFFFF0000u) != 0xA9FE0000u) {
        out.push_back({gw, 1, 0});
    }

    // Priorities 2/3: live IPv4 subnets from getifaddrs().
    struct ifaddrs* ifa = nullptr;
    if (::getifaddrs(&ifa) == 0 && ifa != nullptr) {
        for (struct ifaddrs* p = ifa; p != nullptr; p = p->ifa_next) {
            if (!p->ifa_addr || p->ifa_addr->sa_family != AF_INET) continue;
            if (!(p->ifa_flags & IFF_UP)) continue;
            if (p->ifa_flags & IFF_LOOPBACK) continue;
            if (skip_interface(p->ifa_name ? p->ifa_name : "")) continue;

            const auto* addr = reinterpret_cast<const struct sockaddr_in*>(p->ifa_addr);
            std::uint32_t net = static_cast<std::uint32_t>(::ntohl(addr->sin_addr.s_addr));
            std::uint32_t mask = 0xFFFFFF00u; // sane default for missing netmask
            if (p->ifa_netmask) {
                const auto* nm = reinterpret_cast<const struct sockaddr_in*>(p->ifa_netmask);
                mask = static_cast<std::uint32_t>(::ntohl(nm->sin_addr.s_addr));
            }
            if (mask == 0 || mask == 0xFFFFFFFFu) continue;
            const int group = (net & 0xFFFF0000u) == 0xC0A80000u ? 2 : 3;
            append_subnet_hosts(net, mask, group, out);
        }
        ::freeifaddrs(ifa);
    }

    std::stable_sort(out.begin(), out.end(), [](const Candidate& a, const Candidate& b) {
        if (a.group != b.group) return a.group < b.group;
        return a.order < b.order;
    });

    // Deduplicate (a gateway may also be the first host of a subnet).
    std::vector<Candidate> unique;
    unique.reserve(out.size());
    for (const auto& c : out) {
        if (std::find_if(unique.begin(), unique.end(), [&](const Candidate& u) {
                return u.ip == c.ip;
            }) == unique.end()) {
            unique.push_back(c);
        }
    }
    if (unique.size() > kMaxCandidates) unique.resize(kMaxCandidates);
    return unique;
}

void close_fd(int& fd) {
    if (fd >= 0) {
        ::close(fd);
        fd = -1;
    }
}

bool set_timeouts(int fd, int ms) {
    struct timeval tv{};
    tv.tv_sec = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;
    return ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == 0 &&
           ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) == 0;
}

int connect_nonblocking(std::uint32_t ip, std::uint16_t port) {
    int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    int flags = ::fcntl(fd, F_GETFL, 0);
    if (flags < 0 || ::fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) {
        close_fd(fd);
        return -1;
    }
    struct sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_port = ::htons(port);
    sa.sin_addr.s_addr = ::htonl(ip);
    const int rc = ::connect(fd, reinterpret_cast<struct sockaddr*>(&sa), sizeof(sa));
    if (rc == 0) return fd;
    if (errno != EINPROGRESS && errno != EALREADY) {
        close_fd(fd);
        return -1;
    }
    return fd;
}

int connect_blocking(std::uint32_t ip, std::uint16_t port, int timeoutMs) {
    int fd = connect_nonblocking(ip, port);
    if (fd < 0) return -1;
    struct pollfd pfd{};
    pfd.fd = fd;
    pfd.events = POLLOUT;
    const int r = ::poll(&pfd, 1, std::max(50, timeoutMs));
    if (r <= 0) {
        close_fd(fd);
        return -1;
    }
    int soerr = 0;
    socklen_t len = sizeof(soerr);
    if ((pfd.revents & POLLOUT) == 0 ||
        ::getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &len) != 0 || soerr != 0) {
        close_fd(fd);
        return -1;
    }
    int f = ::fcntl(fd, F_GETFL, 0);
    if (f >= 0) ::fcntl(fd, F_SETFL, f & ~O_NONBLOCK);
    return fd;
}

bool send_all(int fd, const char* data, std::size_t len) {
    std::size_t sent = 0;
    while (sent < len) {
        const ssize_t n = ::send(fd, data + sent, len - sent, MSG_NOSIGNAL);
        if (n <= 0) return false;
        sent += static_cast<std::size_t>(n);
    }
    return true;
}

std::string recv_some(int fd, int timeoutMs) {
    set_timeouts(fd, timeoutMs);
    char buf[256]{};
    const ssize_t n = ::recv(fd, buf, sizeof(buf) - 1, 0);
    if (n <= 0) return {};
    return std::string(buf, static_cast<std::size_t>(n));
}

// Combined SOCKS5 greeting / HTTP-proxy handshake detector. A SOCKS5 server
// answers with 0x05; an HTTP proxy typically answers the bogus greeting with
// "HTTP/1.x 400 ...", which is enough to classify it.
bool probe_on_socket(int fd, int timeoutMs) {
    if (!set_timeouts(fd, timeoutMs)) return false;
    int f = ::fcntl(fd, F_GETFL, 0);
    if (f >= 0) ::fcntl(fd, F_SETFL, f & ~O_NONBLOCK);
    static const char greeting[3] = {5, 1, 0};
    if (!send_all(fd, greeting, sizeof(greeting))) return false;
    const std::string reply = recv_some(fd, timeoutMs);
    if (reply.size() >= 1 && static_cast<unsigned char>(reply[0]) == 5) return true;
    return reply.size() >= 5 && reply.compare(0, 5, "HTTP/") == 0;
}

bool http_connect_probe(std::uint32_t ip, std::uint16_t port, int timeoutMs) {
    int fd = connect_blocking(ip, port, timeoutMs);
    if (fd < 0) return false;
    static const std::string req =
        "CONNECT cp.cloudflare.com:443 HTTP/1.1\r\n"
        "Host: cp.cloudflare.com:443\r\n\r\n";
    bool ok = send_all(fd, req.data(), req.size());
    if (ok) {
        const std::string reply = recv_some(fd, timeoutMs);
        ok = reply.size() >= 7 && reply.compare(0, 7, "HTTP/1.") == 0;
    }
    close_fd(fd);
    return ok;
}

// Returns true when the endpoint really speaks SOCKS5 or HTTP CONNECT.
// This mirrors the original scanner: a local protocol handshake is enough;
// no external CONNECT request is issued for every candidate host.
bool is_proxy(std::uint32_t ip, std::uint16_t port, int timeoutMs) {
    int fd = connect_blocking(ip, port, timeoutMs);
    if (fd < 0) return false;
    bool ok = probe_on_socket(fd, std::max(120, timeoutMs / 2));
    close_fd(fd);
    if (!ok) ok = http_connect_probe(ip, port, std::max(120, timeoutMs / 2));
    return ok;
}

} // namespace

ScanResult scan_lan(int port, std::atomic<bool>* cancel, int timeoutMs) {
    ScanResult result;
    if (port < 1 || port > 65535) return result;
    if (cancelled(cancel)) return result;

    const auto start = Clock::now();
    const int budgetMs = std::max(12000, timeoutMs * 10);
    const int probeMs = std::clamp(timeoutMs, 150, 1000);
    const auto candidates = build_candidates();
    if (candidates.empty()) return result;

    struct Slot {
        int fd{-1};
        std::uint32_t ip{0};
    };

    std::size_t next = 0;
    while (next < candidates.size()) {
        if (cancelled(cancel) || elapsed_ms(start) >= budgetMs) return result;

        std::vector<Slot> slots;
        slots.reserve(kBatchSize);
        for (std::size_t n = 0; n < kBatchSize && next < candidates.size(); ++n, ++next) {
            Slot s;
            s.ip = candidates[next].ip;
            s.fd = connect_nonblocking(s.ip, static_cast<std::uint16_t>(port));
            slots.push_back(s);
        }

        int remainingMs = kBatchPollMs;
        while (remainingMs > 0) {
            if (cancelled(cancel)) {
                for (auto& s : slots) close_fd(s.fd);
                return result;
            }

            std::vector<pollfd> pfds;
            std::vector<std::size_t> owners;
            pfds.reserve(slots.size());
            owners.reserve(slots.size());
            for (std::size_t i = 0; i < slots.size(); ++i) {
                if (slots[i].fd >= 0) {
                    pollfd p{};
                    p.fd = slots[i].fd;
                    p.events = POLLOUT;
                    pfds.push_back(p);
                    owners.push_back(i);
                }
            }
            if (pfds.empty()) break;

            const int step = std::min(kCancelSliceMs, remainingMs);
            const int r = ::poll(pfds.data(), pfds.size(), step);
            remainingMs -= step;
            if (r < 0) {
                if (errno == EINTR) continue;
                break;
            }

            for (std::size_t i = 0; i < pfds.size(); ++i) {
                const short re = pfds[i].revents;
                if (re == 0) continue;
                Slot& s = slots[owners[i]];
                if ((re & POLLOUT) != 0) {
                    int soerr = 0;
                    socklen_t len = sizeof(soerr);
                    if (::getsockopt(s.fd, SOL_SOCKET, SO_ERROR, &soerr, &len) == 0 &&
                        soerr == 0 && is_proxy(s.ip, static_cast<std::uint16_t>(port), probeMs)) {
                        result.found = true;
                        result.ip = u32_to_ip(s.ip);
                        for (auto& item : slots) close_fd(item.fd);
                        return result;
                    }
                }
                close_fd(s.fd);
            }
        }
        for (auto& s : slots) close_fd(s.fd);
    }
    return result;
}

} // namespace tb

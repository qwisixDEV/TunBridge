// Smoke test for the POSIX epoll HTTP bridge with a minimal SOCKS5 server.
#include <tunbridge/net_engine.hpp>

#include <arpa/inet.h>
#include <poll.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <cstring>
#include <iostream>
#include <thread>

namespace {

bool send_all(int fd, const char* data, std::size_t len) {
    while (len > 0) {
        const ssize_t n = ::send(fd, data, len, MSG_NOSIGNAL);
        if (n <= 0) return false;
        data += n;
        len -= static_cast<std::size_t>(n);
    }
    return true;
}

bool recv_some(int fd, char* out, std::size_t want, std::size_t& got, int timeoutMs = 3000) {
    got = 0;
    while (got < want) {
        pollfd pfd{fd, POLLIN, 0};
        if (::poll(&pfd, 1, timeoutMs) <= 0 || !(pfd.revents & POLLIN)) return false;
        const ssize_t n = ::recv(fd, out + got, want - got, 0);
        if (n <= 0) return false;
        got += static_cast<std::size_t>(n);
    }
    return true;
}

int listen_loopback(std::uint16_t& port) {
    int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    int one = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0 ||
        ::listen(fd, 8) != 0) {
        ::close(fd);
        return -1;
    }
    sockaddr_in actual{};
    socklen_t len = sizeof(actual);
    if (::getsockname(fd, reinterpret_cast<sockaddr*>(&actual), &len) != 0) {
        ::close(fd);
        return -1;
    }
    port = ntohs(actual.sin_port);
    return fd;
}

void fake_socks5(int listenFd, std::atomic<bool>& stop) {
    timeval tv{2, 0};
    int client = ::accept(listenFd, nullptr, nullptr);
    if (client < 0) return;
    ::setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    char greeting[4]{};
    std::size_t got = 0;
    if (!recv_some(client, greeting, 3, got)) { ::close(client); return; }
    if (static_cast<unsigned char>(greeting[0]) == 5 &&
        static_cast<unsigned char>(greeting[1]) >= 2) {
        char method = 0;
        if (!recv_some(client, &method, 1, got)) { ::close(client); return; }
    }
    const char methodReply[2] = {5, 0};
    if (!send_all(client, methodReply, 2)) { ::close(client); return; }

    char head[4]{};
    if (!recv_some(client, head, 4, got)) { ::close(client); return; }
    if (static_cast<unsigned char>(head[3]) != 1) { ::close(client); return; }
    char addrPort[6]{};
    if (!recv_some(client, addrPort, 6, got)) { ::close(client); return; }
    const char connectReply[10] = {5, 0, 0, 1, 127, 0, 0, 1, 0, 80};
    if (!send_all(client, connectReply, 10)) { ::close(client); return; }

    char buf[256];
    while (!stop.load(std::memory_order_relaxed)) {
        const ssize_t n = ::recv(client, buf, sizeof(buf), 0);
        if (n <= 0) break;
        if (!send_all(client, buf, static_cast<std::size_t>(n))) break;
    }
    ::close(client);
}

} // namespace

int main() {
    std::uint16_t upstreamPort = 0;
    const int upstreamFd = listen_loopback(upstreamPort);
    if (upstreamFd < 0) {
        std::cerr << "FAIL: cannot create fake SOCKS5 listener\n";
        return 1;
    }

    std::atomic<bool> stop{false};
    std::thread server(fake_socks5, upstreamFd, std::ref(stop));

    tb::NetConfig cfg;
    std::snprintf(cfg.ip, sizeof(cfg.ip), "127.0.0.1");
    cfg.socksPort = upstreamPort;
    cfg.localPort = 0;

    tb::NetStats stats;
    tb::NetEngine engine(cfg, &stats);
    int localPort = 0;
    std::string err;
    bool ok = engine.start(&localPort, &err);
    if (!ok || localPort <= 0) {
        std::cerr << "FAIL: NetEngine::start: " << err << '\n';
        stop = true;
        ::shutdown(upstreamFd, SHUT_RDWR);
        ::close(upstreamFd);
        server.join();
        return 1;
    }

    int client = ::socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(static_cast<std::uint16_t>(localPort));
    ok = client >= 0 && ::connect(client, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0;
    if (ok) {
        const char req[] = "CONNECT example.com:80 HTTP/1.1\r\nHost: example.com:80\r\n\r\n";
        ok = send_all(client, req, sizeof(req) - 1);
    }
    char response[128]{};
    std::size_t got = 0;
    if (ok) ok = recv_some(client, response, 39, got) &&
                 std::strncmp(response, "HTTP/1.1 200", 12) == 0;
    if (ok) ok = send_all(client, "ping", 4);
    char echo[4]{};
    if (ok) ok = recv_some(client, echo, 4, got) && std::memcmp(echo, "ping", 4) == 0;
    if (ok && stats.rx.load() < 4) ok = false;

    if (!ok) std::cerr << "FAIL: local bridge did not relay CONNECT traffic\n";
    if (client >= 0) ::close(client);
    engine.stop();
    stop = true;
    ::shutdown(upstreamFd, SHUT_RDWR);
    ::close(upstreamFd);
    server.join();

    std::cout << (ok ? "PASS: epoll HTTP bridge\n" : "FAIL: epoll HTTP bridge\n");
    return ok ? 0 : 1;
}

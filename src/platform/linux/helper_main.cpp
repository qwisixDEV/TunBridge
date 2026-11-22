#include "tunbridge/helper_protocol.hpp"
#include "tunbridge/privileged.hpp"

#include <array>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <string>

#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

namespace {

volatile sig_atomic_t g_stopRequested = 0;
int g_signalWriteFd = -1;

// Async-signal-safe: only a flag and a single byte into a non-blocking pipe.
void on_signal(int) {
    g_stopRequested = 1;
    if (g_signalWriteFd >= 0) {
        const char byte = 1;
        const ssize_t written = ::write(g_signalWriteFd, &byte, 1);
        (void)written;
    }
}

void install_signals(int writeFd) {
    g_signalWriteFd = writeFd;
    struct sigaction action{};
    action.sa_handler = on_signal;
    ::sigemptyset(&action.sa_mask);
    action.sa_flags = 0;
    (void)::sigaction(SIGTERM, &action, nullptr);
    (void)::sigaction(SIGINT, &action, nullptr);
    (void)::sigaction(SIGHUP, &action, nullptr);

    struct sigaction ignore{};
    ignore.sa_handler = SIG_IGN;
    ::sigemptyset(&ignore.sa_mask);
    (void)::sigaction(SIGPIPE, &ignore, nullptr);
}

bool read_frame(int fd, std::string& text, std::string* err) {
    text.clear();
    std::string buffer;
    std::array<char, 4096> chunk{};
    while (buffer.size() < (1u << 20)) {
        const ssize_t n = ::recv(fd, chunk.data(), chunk.size(), 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            *err = std::string("recv: ") + std::strerror(errno);
            return false;
        }
        if (n == 0) {
            *err = "Клиент закрыл соединение до конца запроса";
            return false;
        }
        buffer.append(chunk.data(), static_cast<std::size_t>(n));
        const std::size_t end = buffer.find("\n\n");
        if (end != std::string::npos) {
            text.assign(buffer, 0, end + 2); // include the terminating empty line
            return true;
        }
    }
    *err = "Слишком большой запрос";
    return false;
}

bool send_all(int fd, const std::string& data) {
    std::size_t offset = 0;
    while (offset < data.size()) {
        const ssize_t n = ::send(fd, data.data() + offset, data.size() - offset, MSG_NOSIGNAL);
        if (n > 0) { offset += static_cast<std::size_t>(n); continue; }
        if (n < 0 && errno == EINTR) continue;
        return false;
    }
    return true;
}

// Blocks with zero CPU usage until the watchdog channel closes or a signal
// arrives. No polling loops with sleeps and no busy waiting.
void wait_for_channel_close(int fd, int signalFd) {
    while (!g_stopRequested) {
        struct pollfd fds[2]{};
        fds[0].fd = fd;
        fds[0].events = POLLIN;
        fds[1].fd = signalFd;
        fds[1].events = POLLIN;

        const int rc = ::ppoll(fds, 2, nullptr, nullptr);
        if (rc < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (fds[1].revents & POLLIN) {
            std::array<char, 64> drain{};
            while (::read(signalFd, drain.data(), drain.size()) > 0) { /* drain */ }
            break;
        }
        if (fds[0].revents & (POLLIN | POLLHUP | POLLERR | POLLNVAL)) {
            std::array<char, 256> ignore{};
            const ssize_t n = ::recv(fd, ignore.data(), ignore.size(), MSG_DONTWAIT);
            if (n <= 0) break;
        }
    }
}

bool connect_to_gui(const std::string& path, int* fdOut, std::string* err) {
    *fdOut = -1;
    struct sockaddr_un addr{};
    if (path.empty() || path.size() + 1 > sizeof(addr.sun_path)) {
        *err = "Некорректный путь сокета помощника";
        return false;
    }
    std::memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    std::memcpy(addr.sun_path, path.c_str(), path.size());

    const int fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        *err = std::string("socket: ") + std::strerror(errno);
        return false;
    }
    int flags = ::fcntl(fd, F_GETFL, 0);
    if (flags < 0 || ::fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) {
        *err = std::string("fcntl: ") + std::strerror(errno);
        ::close(fd);
        return false;
    }
    if (::connect(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) != 0) {
        if (errno != EINPROGRESS && errno != EALREADY) {
            *err = std::string("connect: ") + std::strerror(errno);
            ::close(fd);
            return false;
        }
        struct pollfd pfd{};
        pfd.fd = fd;
        pfd.events = POLLOUT;
        const int rc = ::poll(&pfd, 1, 5000);
        if (rc <= 0) {
            *err = rc == 0 ? "Тайм-аут подключения к GUI" : std::string("poll: ") + std::strerror(errno);
            ::close(fd);
            return false;
        }
        int socketError = 0;
        socklen_t len = sizeof(socketError);
        if (::getsockopt(fd, SOL_SOCKET, SO_ERROR, &socketError, &len) != 0 || socketError != 0) {
            *err = std::string("connect: ") + std::strerror(socketError);
            ::close(fd);
            return false;
        }
    }
    if (flags >= 0) (void)::fcntl(fd, F_SETFL, flags);
    struct timeval tv{};
    tv.tv_sec = 10;
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    *fdOut = fd;
    return true;
}

} // namespace

int main(int argc, char** argv) {
    if (!tb::privileged_is_root()) {
        std::fprintf(stderr,
                     "TunBridge helper: требуются права root. "
                     "Запуск только через pkexec (получен euid != 0).\n");
        return 1;
    }

    std::string socketPath;
    for (int i = 1; i < argc; ++i) {
        if (argv[i] && std::strcmp(argv[i], "--socket") == 0 && i + 1 < argc) {
            socketPath = argv[++i];
            break;
        }
    }
    if (socketPath.empty()) {
        std::fprintf(stderr, "TunBridge helper: отсутствует аргумент --socket <path>.\n");
        return 2;
    }

    int signalFds[2] = {-1, -1};
    if (::pipe2(signalFds, O_CLOEXEC | O_NONBLOCK) != 0) {
        std::fprintf(stderr, "TunBridge helper: pipe2: %s\n", std::strerror(errno));
        return 3;
    }
    install_signals(signalFds[1]);

    std::string err;
    int fd = -1;
    if (!connect_to_gui(socketPath, &fd, &err)) {
        std::fprintf(stderr, "TunBridge helper: %s\n", err.c_str());
        ::close(signalFds[0]);
        ::close(signalFds[1]);
        return 4;
    }

    tb::PrivilegedState state;
    tb::HelperRequest request;
    tb::HelperReply reply;
    bool rollbackOnExit = false;
    bool waitForClose = false;

    std::string requestText;
    if (!read_frame(fd, requestText, &err) || !tb::decode_request(requestText, request)) {
        reply.ok = false;
        reply.message = err.empty() ? "Некорректный запрос помощника" : err;
    } else if (!tb::set_privileged_runtime_dir(request.runtimeDir)) {
        reply.ok = false;
        reply.message = "Некорректный XDG_RUNTIME_DIR в запросе";
    } else {
        std::string detail;
        switch (request.action) {
            case tb::HelperAction::Ping:
                reply.ok = true;
                reply.message = "PONG (root)";
                if (state.zapret_active(&detail) && !detail.empty())
                    reply.message += "; " + detail;
                break;
            case tb::HelperAction::StartTun:
                reply.ok = state.start_tun(request, &detail);
                reply.message = detail.empty() ? (reply.ok ? "TUN запущен" : "Ошибка запуска TUN")
                                               : detail;
                rollbackOnExit = reply.ok;
                waitForClose = true;
                break;
            case tb::HelperAction::StopTun:
                reply.ok = state.stop_tun(&detail);
                reply.message = detail;
                waitForClose = true;
                break;
            case tb::HelperAction::StopZapret:
                reply.ok = state.stop_zapret(&detail);
                reply.message = detail;
                waitForClose = true;
                break;
            case tb::HelperAction::RestoreZapret:
                reply.ok = state.restore_zapret(&detail);
                reply.message = detail;
                waitForClose = true;
                break;
            default:
                reply.ok = false;
                reply.message = "Неизвестное действие";
                break;
        }
    }

    (void)send_all(fd, tb::encode_reply(reply));

    if (waitForClose) wait_for_channel_close(fd, signalFds[0]);
    if (rollbackOnExit) state.rollback();
    else state.commit();

    ::close(fd);
    ::close(signalFds[0]);
    ::close(signalFds[1]);
    return 0;
}

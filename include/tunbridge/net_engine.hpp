#pragma once

#include "tunbridge/core.hpp"

#include <atomic>
#include <cstdint>
#include <memory>
#include <string>

namespace tb {

struct NetStats {
    std::atomic<std::uint64_t> rx{0};
    std::atomic<std::uint64_t> tx{0};
    std::atomic<std::uint32_t> connections{0};
};

// Event-driven local HTTP proxy. One epoll thread, no thread-per-connection.
class NetEngine {
public:
    explicit NetEngine(NetConfig cfg, NetStats* stats);
    ~NetEngine();
    NetEngine(const NetEngine&) = delete;
    NetEngine& operator=(const NetEngine&) = delete;

    // Starts the epoll thread and waits until the listener is ready.
    bool start(int* boundPort, std::string* err);
    void stop();
    int port() const;
    bool running() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace tb

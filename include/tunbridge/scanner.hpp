#pragma once

#include <atomic>
#include <cstdint>
#include <string>

namespace tb {

struct ScanResult {
    bool found{false};
    std::string ip;
};

// getifaddrs() + batched non-blocking connect()/poll(). No thread per host.
ScanResult scan_lan(int port, std::atomic<bool>* cancel, int timeoutMs = 1200);

} // namespace tb

// Linux sysfs traffic counters for the tun interface.
// Only standard C++20 + POSIX are used.

#include "tunbridge/traffic.hpp"

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>

namespace tb {
namespace {

bool read_counter(const std::string& iface, const char* name, std::uint64_t& value) {
    value = 0;
    // Reject path separators and relative names; only a plain interface name
    // from /sys/class/net is accepted.
    if (iface.empty() || iface.find('/') != std::string::npos ||
        iface.find('\\') != std::string::npos || iface[0] == '.' ||
        iface.size() > 255) {
        return false;
    }

    const std::string path = "/sys/class/net/" + iface + "/statistics/" + name;
    std::error_code ec;
    if (!std::filesystem::is_regular_file(path, ec) || ec) return false;

    std::ifstream f(path);
    if (!f) return false;
    f >> value;
    if (f.fail()) {
        value = 0;
        return false;
    }
    return true;
}

} // namespace

bool read_tun_traffic(const std::string& iface, std::uint64_t& rx, std::uint64_t& tx) {
    rx = 0;
    tx = 0;
    if (!read_counter(iface, "rx_bytes", rx)) {
        rx = 0;
        return false;
    }
    if (!read_counter(iface, "tx_bytes", tx)) {
        rx = 0;
        tx = 0;
        return false;
    }
    return true;
}

std::uint64_t read_tun_traffic_bytes(const std::string& iface) {
    std::uint64_t rx = 0, tx = 0;
    if (!read_tun_traffic(iface, rx, tx)) return 0;
    return rx + tx;
}

} // namespace tb

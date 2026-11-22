#pragma once

#include <cstdint>
#include <string>

namespace tb {

// Reads /sys/class/net/<iface>/statistics/{rx,tx}_bytes. Returns the sum.
std::uint64_t read_tun_traffic_bytes(const std::string& iface);
bool read_tun_traffic(const std::string& iface, std::uint64_t& rx, std::uint64_t& tx);

} // namespace tb

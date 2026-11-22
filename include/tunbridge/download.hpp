#pragma once

#include <string>

namespace tb {

// Downloads the official tun2socks Linux release into
// $XDG_DATA_HOME/tunbridge/bin, verifies the published SHA-256 digest and
// makes the binary executable. Uses libcurl + OpenSSL.
bool download_tun2socks(std::string* status, std::string* error);
std::string tun2socks_path();

} // namespace tb

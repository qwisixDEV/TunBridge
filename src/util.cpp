#include "tunbridge/common.hpp"

#include <filesystem>

// --- Безопасные хелперы ---
void SafeCopyA(char* d, size_t n, const char* s) {
    if (!d || !n) return;
    if (!s) { d[0] = 0; return; }
    size_t i = 0; for (; i + 1 < n && s[i]; i++) d[i] = s[i];
    d[i] = 0;
}
void SafeCopyW(wchar_t* d, size_t n, const wchar_t* s) {
    if (!d || !n) return;
    if (!s) { d[0] = 0; return; }
    size_t i = 0; for (; i + 1 < n && s[i]; i++) d[i] = s[i];
    d[i] = 0;
}
bool IsSafeHostString(const char* s) {
    if (!s || !s[0]) return false;
    for (int i = 0; s[i]; i++) {
        unsigned char c = (unsigned char)s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '.' || c == '-')) return false;
    }
    return true;
}
bool ComputeFileSha256Hex(const wchar_t* path, char outHex[65]) {
    if (!path) { if (outHex) outHex[0] = 0; return false; }
    return tb::sha256_file_hex(std::filesystem::path(path).string(), outHex);
}
PIP_ADAPTER_ADDRESSES AllocAdapters() {
    ULONG sz = 32768;
    PIP_ADAPTER_ADDRESSES a = (PIP_ADAPTER_ADDRESSES)malloc(sz);
    if (!a) return nullptr;
    DWORD r = GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER, nullptr, a, &sz);
    if (r == ERROR_BUFFER_OVERFLOW) {
        free(a); a = (PIP_ADAPTER_ADDRESSES)malloc(sz);
        if (!a) return nullptr;
        r = GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER, nullptr, a, &sz);
    }
    if (r != NO_ERROR) { free(a); return nullptr; }
    return a;
}

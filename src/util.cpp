#include "tunbridge/common.hpp"

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
    outHex[0] = 0;
    HANDLE hf = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (hf == INVALID_HANDLE_VALUE) return false;
    HCRYPTPROV hp = 0; HCRYPTHASH hh = 0; bool ok = false;
    if (CryptAcquireContextW(&hp, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        if (CryptCreateHash(hp, CALG_SHA_256, 0, 0, &hh)) {
            BYTE buf[32768]; DWORD br = 0; bool rdOk = true;
            while (ReadFile(hf, buf, sizeof(buf), &br, nullptr) && br > 0)
                if (!CryptHashData(hh, buf, br, 0)) { rdOk = false; break; }
            BYTE dig[32] = {}; DWORD dl = 32;
            if (rdOk && CryptGetHashParam(hh, HP_HASHVAL, dig, &dl, 0) && dl == 32) {
                static const char hx[] = "0123456789abcdef";
                for (int i = 0; i < 32; i++) { outHex[i*2] = hx[dig[i]>>4]; outHex[i*2+1] = hx[dig[i]&15]; }
                outHex[64] = 0; ok = true;
            }
            CryptDestroyHash(hh);
        }
        CryptReleaseContext(hp, 0);
    }
    CloseHandle(hf);
    return ok;
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

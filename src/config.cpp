#include "tunbridge/config.hpp"

void GetNetConfig(NetConfig* out) {
    EnterCriticalSection(&g_cfgCs); *out = g_cfg; LeaveCriticalSection(&g_cfgCs);
}

// --- Автозапуск ---
bool IsAutoStartEnabled() {
    HKEY hk; bool on = false;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, REG_WIN_RUN, 0, KEY_READ, &hk) == ERROR_SUCCESS) {
        wchar_t v[MAX_PATH * 2] = {}; DWORD sz = sizeof(v) - sizeof(wchar_t), tp = 0;
        if (RegQueryValueExW(hk, RUN_VAL_NAME, nullptr, &tp, (LPBYTE)v, &sz) == ERROR_SUCCESS &&
            (tp == REG_SZ || tp == REG_EXPAND_SZ) && v[0]) on = true;
        RegCloseKey(hk);
    }
    return on;
}
bool SetAutoStartEnabled(bool on) {
    HKEY hk;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, REG_WIN_RUN, 0, nullptr, 0, KEY_WRITE, nullptr, &hk, nullptr) != ERROR_SUCCESS) return false;
    LONG rc;
    if (on) {
        wchar_t cmd[MAX_PATH + 32]; _snwprintf(cmd, MAX_PATH + 31, L"\"%s\" --minimized", g_exePath); cmd[MAX_PATH + 31] = 0;
        rc = RegSetValueExW(hk, RUN_VAL_NAME, 0, REG_SZ, (const BYTE*)cmd, (DWORD)((wcslen(cmd) + 1) * sizeof(wchar_t)));
    } else {
        rc = RegDeleteValueW(hk, RUN_VAL_NAME);
        if (rc == ERROR_FILE_NOT_FOUND) rc = ERROR_SUCCESS;
    }
    RegCloseKey(hk); return rc == ERROR_SUCCESS;
}

// --- Конфигурация ---
static void NormalizeIpAndPortInUi() {
    if (!hEditIp) return;
    char buf[128] = {}; GetWindowTextA(hEditIp, buf, 127);
    int j = 0; for (int i = 0; buf[i]; i++) if (buf[i] > ' ') buf[j++] = buf[i]; buf[j] = 0;
    char* col = strchr(buf, ':');
    if (col && !strchr(col + 1, ':')) {
        int p = atoi(col + 1); *col = 0; SetWindowTextA(hEditIp, buf);
        if (p > 0 && p <= 65535) {
            EnterCriticalSection(&g_cfgCs); g_cfg.socksPort = p; LeaveCriticalSection(&g_cfgCs);
            if (hEditSPort) { char ps[16]; snprintf(ps, sizeof(ps), "%d", p); SetWindowTextA(hEditSPort, ps); }
        }
    }
}
void SaveConfig() {
    NormalizeIpAndPortInUi();
    EnterCriticalSection(&g_cfgCs);
    if (hEditIp)   { GetWindowTextA(hEditIp, g_cfg.ip, sizeof(g_cfg.ip) - 1); g_cfg.ip[sizeof(g_cfg.ip)-1] = 0; }
    if (hEditUser) { GetWindowTextA(hEditUser, g_cfg.user, sizeof(g_cfg.user) - 1); g_cfg.user[sizeof(g_cfg.user)-1] = 0; }
    if (hEditPass) { GetWindowTextA(hEditPass, g_cfg.pass, sizeof(g_cfg.pass) - 1); g_cfg.pass[sizeof(g_cfg.pass)-1] = 0; }
    if (hEditSPort){ char b[16]={}; GetWindowTextA(hEditSPort, b, 15); int v = atoi(b); if (v > 0 && v <= 65535) g_cfg.socksPort = v; }
    if (hEditLPort){ char b[16]={}; GetWindowTextA(hEditLPort, b, 15); int v = atoi(b); if (v > 0 && v <= 65535) g_cfg.localPort = v; }
    NetConfig snap = g_cfg;
    LeaveCriticalSection(&g_cfgCs);

    HKEY hk;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, REG_APP_CFG, 0, nullptr, 0, KEY_WRITE, nullptr, &hk, nullptr) == ERROR_SUCCESS) {
        auto SetDw = [&](const wchar_t* k, DWORD v){ RegSetValueExW(hk, k, 0, REG_DWORD, (const BYTE*)&v, sizeof(v)); };
        RegSetValueExA(hk, "PhoneIp", 0, REG_SZ, (const BYTE*)snap.ip, (DWORD)strlen(snap.ip) + 1);
        RegSetValueExA(hk, "User",    0, REG_SZ, (const BYTE*)snap.user, (DWORD)strlen(snap.user) + 1);
        RegSetValueExA(hk, "Pass",    0, REG_SZ, (const BYTE*)snap.pass, (DWORD)strlen(snap.pass) + 1);
        SetDw(L"SocksPort", (DWORD)snap.socksPort); SetDw(L"LocalPort", (DWORD)snap.localPort);
        SetDw(L"Mode", (DWORD)g_mode); SetDw(L"MinimizeToTray", (DWORD)g_minimizeToTray);
        SetDw(L"AutoRestoreZapret", (DWORD)g_autoRestoreZapret);
        RegCloseKey(hk);
    }
}
void LoadConfig() {
    HKEY hk;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, REG_APP_CFG, 0, KEY_READ, &hk) == ERROR_SUCCESS) {
        auto GetStr = [&](const char* k, char* d, size_t n){
            DWORD tp = 0, sz = (DWORD)(n - 1);
            if (RegQueryValueExA(hk, k, nullptr, &tp, (LPBYTE)d, &sz) == ERROR_SUCCESS && tp == REG_SZ) d[sz < n ? sz : n - 1] = 0;
        };
        auto GetDw = [&](const wchar_t* k, DWORD* out){
            DWORD tp = 0, sz = sizeof(DWORD);
            return RegQueryValueExW(hk, k, nullptr, &tp, (LPBYTE)out, &sz) == ERROR_SUCCESS && tp == REG_DWORD;
        };
        EnterCriticalSection(&g_cfgCs);
        GetStr("PhoneIp", g_cfg.ip, sizeof(g_cfg.ip));
        GetStr("User", g_cfg.user, sizeof(g_cfg.user));
        GetStr("Pass", g_cfg.pass, sizeof(g_cfg.pass));
        DWORD dw = 0;
        if (GetDw(L"SocksPort", &dw) && dw > 0 && dw <= 65535) g_cfg.socksPort = (int)dw;
        if (GetDw(L"LocalPort", &dw) && dw > 0 && dw <= 65535) g_cfg.localPort = (int)dw;
        LeaveCriticalSection(&g_cfgCs);
        if (GetDw(L"Mode", &dw) && (dw == 0 || dw == 1)) g_mode = (int)dw;
        if (GetDw(L"MinimizeToTray", &dw)) g_minimizeToTray = dw ? 1 : 0;
        if (GetDw(L"AutoRestoreZapret", &dw)) g_autoRestoreZapret = dw ? 1 : 0;
        RegCloseKey(hk);
    }
    g_autoStart = IsAutoStartEnabled();
}
void SetWindowsProxy(bool enable, int localPort) {
    HKEY hk;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, REG_WIN_INET, 0, KEY_WRITE, &hk) == ERROR_SUCCESS) {
        DWORD v = enable ? 1 : 0; RegSetValueExW(hk, L"ProxyEnable", 0, REG_DWORD, (const BYTE*)&v, sizeof(v));
        if (enable) {
            wchar_t srv[64]; _snwprintf(srv, 63, L"127.0.0.1:%d", localPort); srv[63] = 0;
            RegSetValueExW(hk, L"ProxyServer", 0, REG_SZ, (const BYTE*)srv, (DWORD)((wcslen(srv) + 1) * sizeof(wchar_t)));
            const wchar_t* by = L"localhost;127.*;10.*;172.16.*;192.168.*;<local>";
            RegSetValueExW(hk, L"ProxyOverride", 0, REG_SZ, (const BYTE*)by, (DWORD)((wcslen(by) + 1) * sizeof(wchar_t)));
        }
        RegCloseKey(hk);
    }
    if (RegCreateKeyExW(HKEY_CURRENT_USER, REG_APP_CFG, 0, nullptr, 0, KEY_WRITE, nullptr, &hk, nullptr) == ERROR_SUCCESS) {
        DWORD m = enable ? 1 : 0; RegSetValueExW(hk, L"WeSetProxy", 0, REG_DWORD, (const BYTE*)&m, sizeof(m)); RegCloseKey(hk);
    }
    InternetSetOptionW(nullptr, INTERNET_OPTION_SETTINGS_CHANGED, nullptr, 0);
    InternetSetOptionW(nullptr, INTERNET_OPTION_REFRESH, nullptr, 0);
}

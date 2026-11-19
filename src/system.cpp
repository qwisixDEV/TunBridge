#include "tunbridge/system.hpp"
#include "tunbridge/config.hpp"

// --- Система, права, процессы, службы ---
void EnableDpiAwareness() {
    HMODULE h = GetModuleHandleW(L"user32.dll");
    if (!h) return;
    auto pCtx = (BOOL(WINAPI*)(HANDLE))GetProcAddress(h, "SetProcessDpiAwarenessContext");
    if (pCtx && pCtx((HANDLE)(INT_PTR)-4)) return;
    auto pAw = (BOOL(WINAPI*)())GetProcAddress(h, "SetProcessDPIAware");
    if (pAw) pAw();
}
float QuerySystemScale() {
    HDC hdc = GetDC(nullptr); int dpi = GetDeviceCaps(hdc, LOGPIXELSY); ReleaseDC(nullptr, hdc);
    return dpi > 0 ? (float)dpi / 96.0f : 1.0f;
}
void InitExePaths() {
    DWORD n = GetModuleFileNameW(nullptr, g_exePath, MAX_PATH);
    if (n >= MAX_PATH) g_exePath[MAX_PATH - 1] = 0;
    SafeCopyW(g_exeDir, MAX_PATH, g_exePath);
    wchar_t* sl = wcsrchr(g_exeDir, L'\\'); if (sl) *sl = 0;
}
static bool FileExistsW(const wchar_t* p) { DWORD a = GetFileAttributesW(p); return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY); }
bool IsElevated() {
    BOOL el = FALSE; HANDLE tok = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) {
        TOKEN_ELEVATION te = {}; DWORD sz = sizeof(te);
        if (GetTokenInformation(tok, TokenElevation, &te, sizeof(te), &sz)) el = te.TokenIsElevated;
        CloseHandle(tok);
    }
    return el != FALSE;
}
bool FindTunBinaries(wchar_t* outExe, wchar_t* outDll) {
    _snwprintf(outDll, MAX_PATH - 1, L"%s\\wintun.dll", g_exeDir); outDll[MAX_PATH - 1] = 0;
    if (!FileExistsW(outDll)) return false;
    _snwprintf(outExe, MAX_PATH - 1, L"%s\\tun2socks.exe", g_exeDir); outExe[MAX_PATH - 1] = 0;
    if (FileExistsW(outExe)) return true;
    _snwprintf(outExe, MAX_PATH - 1, L"%s\\tun2socks-windows-amd64.exe", g_exeDir); outExe[MAX_PATH - 1] = 0;
    return FileExistsW(outExe);
}
DWORD RunHiddenWait(const wchar_t* cmd, DWORD ms) {
    wchar_t buf[4096]; SafeCopyW(buf, 4096, cmd);
    STARTUPINFOW si = { sizeof(si) }; si.dwFlags = STARTF_USESHOWWINDOW; si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = {};
    if (!CreateProcessW(nullptr, buf, nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, g_exeDir, &si, &pi)) return (DWORD)-1;
    WaitForSingleObject(pi.hProcess, ms);
    DWORD code = (DWORD)-1; GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess); return code;
}
static bool RunHiddenCaptureUtf8(const wchar_t* cmd, char* out, int outSz, DWORD ms) {
    if (!out || outSz <= 0) return false;
    out[0] = 0;
    SECURITY_ATTRIBUTES sa = { sizeof(sa), nullptr, TRUE };
    HANDLE hr = nullptr, hw = nullptr;
    if (!CreatePipe(&hr, &hw, &sa, 0)) return false;
    SetHandleInformation(hr, HANDLE_FLAG_INHERIT, 0);
    wchar_t buf[2048]; SafeCopyW(buf, 2048, cmd);
    STARTUPINFOW si = { sizeof(si) }; si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
    si.wShowWindow = SW_HIDE; si.hStdOutput = hw; si.hStdError = hw;
    PROCESS_INFORMATION pi = {};
    if (!CreateProcessW(nullptr, buf, nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, g_exeDir, &si, &pi)) {
        CloseHandle(hw); CloseHandle(hr); return false;
    }
    CloseHandle(hw);
    int tot = 0; DWORD br = 0;
    while (tot < outSz - 1 && ReadFile(hr, out + tot, (DWORD)(outSz - 1 - tot), &br, nullptr) && br > 0) tot += (int)br;
    out[tot] = 0; CloseHandle(hr);
    WaitForSingleObject(pi.hProcess, ms); CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    return tot > 0;
}
static bool IsProcessRunning(const wchar_t* exe, wchar_t* outPath = nullptr, int maxPath = 0) {
    HANDLE sp = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (sp == INVALID_HANDLE_VALUE) return false;
    PROCESSENTRY32W pe = { sizeof(pe) }; bool found = false;
    if (Process32FirstW(sp, &pe)) do {
        if (_wcsicmp(pe.szExeFile, exe) == 0) {
            found = true;
            if (outPath && maxPath > 0) {
                outPath[0] = 0;
                HANDLE hp = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
                if (hp) { DWORD sz = (DWORD)maxPath; if (!QueryFullProcessImageNameW(hp, 0, outPath, &sz)) outPath[0] = 0; CloseHandle(hp); }
            }
            break;
        }
    } while (Process32NextW(sp, &pe));
    CloseHandle(sp); return found;
}
static int KillProcessesByName(const wchar_t* exe) {
    HANDLE sp = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (sp == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe = { sizeof(pe) }; DWORD self = GetCurrentProcessId(); int k = 0;
    if (Process32FirstW(sp, &pe)) do {
        if (pe.th32ProcessID != self && _wcsicmp(pe.szExeFile, exe) == 0) {
            HANDLE hp = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, pe.th32ProcessID);
            if (hp) { if (TerminateProcess(hp, 0)) { WaitForSingleObject(hp, 1500); k++; } CloseHandle(hp); }
        }
    } while (Process32NextW(sp, &pe));
    CloseHandle(sp); return k;
}
static bool IsServiceRunning(const wchar_t* name) {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT); if (!scm) return false;
    SC_HANDLE svc = OpenServiceW(scm, name, SERVICE_QUERY_STATUS); bool run = false;
    if (svc) { SERVICE_STATUS st = {}; if (QueryServiceStatus(svc, &st)) run = (st.dwCurrentState != SERVICE_STOPPED); CloseServiceHandle(svc); }
    CloseServiceHandle(scm); return run;
}
static bool StopServiceByName(const wchar_t* name, DWORD waitMs) {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT); if (!scm) return false;
    SC_HANDLE svc = OpenServiceW(scm, name, SERVICE_STOP | SERVICE_QUERY_STATUS); bool ok = false;
    if (svc) {
        SERVICE_STATUS st = {};
        if (QueryServiceStatus(svc, &st)) {
            if (st.dwCurrentState == SERVICE_STOPPED) ok = true;
            else {
                if (st.dwCurrentState != SERVICE_STOP_PENDING) ControlService(svc, SERVICE_CONTROL_STOP, &st);
                ULONGLONG t0 = GetTickCount64();
                while (GetTickCount64() - t0 < waitMs) {
                    if (!QueryServiceStatus(svc, &st) || st.dwCurrentState == SERVICE_STOPPED) { ok = true; break; }
                    Sleep(100);
                }
            }
        }
        CloseServiceHandle(svc);
    }
    CloseServiceHandle(scm); return ok;
}
static bool StartServiceByName(const wchar_t* name, DWORD waitMs) {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT); if (!scm) return false;
    SC_HANDLE svc = OpenServiceW(scm, name, SERVICE_START | SERVICE_QUERY_STATUS); bool ok = false;
    if (svc) {
        SERVICE_STATUS st = {};
        ULONGLONG t0 = GetTickCount64();
        // Ждём, если служба ещё доостанавливается (SERVICE_STOP_PENDING)
        while (QueryServiceStatus(svc, &st) && st.dwCurrentState == SERVICE_STOP_PENDING && GetTickCount64() - t0 < waitMs) Sleep(100);
        if (st.dwCurrentState == SERVICE_RUNNING) ok = true;
        else if (StartServiceW(svc, 0, nullptr) || GetLastError() == ERROR_SERVICE_ALREADY_RUNNING) {
            t0 = GetTickCount64();
            while (GetTickCount64() - t0 < waitMs) {
                if (!QueryServiceStatus(svc, &st)) break;
                if (st.dwCurrentState == SERVICE_RUNNING) { ok = true; break; }
                if (st.dwCurrentState != SERVICE_START_PENDING) break;
                Sleep(100);
            }
        }
        CloseServiceHandle(svc);
    }
    CloseServiceHandle(scm); return ok;
}

static const wchar_t* const ZAPRET_SVCS[] = { L"zapret", L"winws", L"winws1", L"winws2", L"GoodbyeDPI" };
static const wchar_t* const ZAPRET_EXES[] = { L"winws.exe", L"winws2.exe", L"goodbyedpi.exe" };

// --- Zapret / WinDivert ---
bool IsZapretActive() {
    for (auto e : ZAPRET_EXES) if (IsProcessRunning(e)) return true;
    for (auto s : ZAPRET_SVCS) if (IsServiceRunning(s)) return true;
    return false;
}
void ClearSavedZapretState() {
    g_stoppedZapretSvc[0] = g_stoppedZapretExe[0] = g_stoppedZapretWorkDir[0] = g_stoppedZapretCmdLine[0] = 0;
}
void CaptureZapretStateBeforeStop() {
    ClearSavedZapretState();
    for (auto s : ZAPRET_SVCS) if (IsServiceRunning(s)) { SafeCopyW(g_stoppedZapretSvc, 64, s); return; }
    bool found = false;
    for (auto e : ZAPRET_EXES) if (IsProcessRunning(e, g_stoppedZapretExe, MAX_PATH)) { found = true; break; }
    if (!found) return;

    char cmdUtf8[8192] = {};
    const wchar_t* ps =
        L"powershell -NoProfile -ExecutionPolicy Bypass -Command \""
        L"[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; "
        L"$p=Get-CimInstance Win32_Process | Where-Object { $_.Name -in @('winws.exe','winws2.exe','goodbyedpi.exe') } | Select-Object -First 1; "
        L"if ($p) { [Console]::Out.Write($p.CommandLine) }\"";
    if (RunHiddenCaptureUtf8(ps, cmdUtf8, sizeof(cmdUtf8), 4000)) {
        int len = (int)strlen(cmdUtf8);
        while (len > 0 && (cmdUtf8[len-1] == '\r' || cmdUtf8[len-1] == '\n')) cmdUtf8[--len] = 0;
        if (len > 0) {
            MultiByteToWideChar(CP_UTF8, 0, cmdUtf8, -1, g_stoppedZapretCmdLine, 8192);
            g_stoppedZapretCmdLine[8191] = 0;
        }
    }
    if (g_stoppedZapretExe[0]) {
        SafeCopyW(g_stoppedZapretWorkDir, MAX_PATH, g_stoppedZapretExe);
        wchar_t* sl = wcsrchr(g_stoppedZapretWorkDir, L'\\');
        if (sl) {
            *sl = 0;
            size_t wl = wcslen(g_stoppedZapretWorkDir);
            if (wl > 4 && _wcsicmp(g_stoppedZapretWorkDir + wl - 4, L"\\bin") == 0) g_stoppedZapretWorkDir[wl - 4] = 0;
        }
    }
}
void StopZapret() {
    for (auto s : ZAPRET_SVCS) StopServiceByName(s, 2500);
    for (auto e : ZAPRET_EXES) KillProcessesByName(e);
    Sleep(150);
    StopServiceByName(L"WinDivert", 2000);
    StopServiceByName(L"WinDivert1.4", 2000);
}
void RestoreZapretIfNeeded() {
    if (!g_autoRestoreZapret) { ClearSavedZapretState(); return; }
    if (g_stoppedZapretSvc[0]) { StartServiceByName(g_stoppedZapretSvc, 3000); ClearSavedZapretState(); return; }
    if (g_stoppedZapretCmdLine[0] || g_stoppedZapretExe[0]) {
        wchar_t cmdCopy[8192] = {};
        if (g_stoppedZapretCmdLine[0]) {
            size_t exLen = wcslen(g_stoppedZapretExe);
            if (exLen > 0 && g_stoppedZapretCmdLine[0] != L'"' &&
                _wcsnicmp(g_stoppedZapretCmdLine, g_stoppedZapretExe, exLen) == 0 &&
                (g_stoppedZapretCmdLine[exLen] == L' ' || g_stoppedZapretCmdLine[exLen] == 0)) {
                _snwprintf(cmdCopy, 8191, L"\"%s\"%s", g_stoppedZapretExe, g_stoppedZapretCmdLine + exLen);
                cmdCopy[8191] = 0;
            } else {
                SafeCopyW(cmdCopy, 8192, g_stoppedZapretCmdLine);
            }
        } else {
            _snwprintf(cmdCopy, 8191, L"\"%s\"", g_stoppedZapretExe); cmdCopy[8191] = 0;
        }
        STARTUPINFOW si = { sizeof(si) }; si.dwFlags = STARTF_USESHOWWINDOW; si.wShowWindow = SW_HIDE;
        PROCESS_INFORMATION pi = {};
        const wchar_t* app = g_stoppedZapretExe[0] ? g_stoppedZapretExe : nullptr;
        const wchar_t* wd  = g_stoppedZapretWorkDir[0] ? g_stoppedZapretWorkDir : nullptr;
        if (CreateProcessW(app, cmdCopy, nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, wd, &si, &pi)) {
            CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        }
        ClearSavedZapretState();
    }
}
void CleanupOrphanedTunProcesses() {
    if (KillProcessesByName(L"tun2socks.exe") + KillProcessesByName(L"tun2socks-windows-amd64.exe") > 0) Sleep(250);
}
void SaveLastPhoneRouteIp(const char* ip) {
    HKEY hk;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, REG_APP_CFG, 0, nullptr, 0, KEY_WRITE, nullptr, &hk, nullptr) == ERROR_SUCCESS) {
        if (ip && ip[0]) RegSetValueExA(hk, "LastPhoneRouteIp", 0, REG_SZ, (const BYTE*)ip, (DWORD)strlen(ip) + 1);
        else RegDeleteValueA(hk, "LastPhoneRouteIp");
        RegCloseKey(hk);
    }
}
void CleanupSavedPhoneRouteFromReg() {
    HKEY hk;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, REG_APP_CFG, 0, KEY_READ | KEY_WRITE, &hk) == ERROR_SUCCESS) {
        char ip[64] = {}; DWORD sz = sizeof(ip) - 1, tp = 0;
        if (RegQueryValueExA(hk, "LastPhoneRouteIp", nullptr, &tp, (LPBYTE)ip, &sz) == ERROR_SUCCESS && tp == REG_SZ) {
            ip[sz < sizeof(ip) ? sz : sizeof(ip) - 1] = 0;
            if (IsSafeHostString(ip)) {
                wchar_t cmd[256]; _snwprintf(cmd, 255, L"route delete %hs mask 255.255.255.255", ip); cmd[255] = 0;
                RunHiddenWait(cmd, 2000);
            }
            RegDeleteValueA(hk, "LastPhoneRouteIp");
        }
        RegCloseKey(hk);
    }
}
void CleanupStaleStateOnStartup() {
    HKEY hk;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, REG_APP_CFG, 0, KEY_READ | KEY_WRITE, &hk) == ERROR_SUCCESS) {
        DWORD m = 0, sz = sizeof(m), tp = 0;
        bool needOff = (RegQueryValueExW(hk, L"WeSetProxy", nullptr, &tp, (LPBYTE)&m, &sz) == ERROR_SUCCESS && tp == REG_DWORD && m == 1);
        RegCloseKey(hk);
        if (needOff) SetWindowsProxy(false, g_cfg.localPort);
    }
    CleanupOrphanedTunProcesses();
    if (IsElevated()) {
        RunHiddenWait(L"route delete 0.0.0.0 mask 128.0.0.0", 2000);
        RunHiddenWait(L"route delete 128.0.0.0 mask 128.0.0.0", 2000);
        CleanupSavedPhoneRouteFromReg();
    }
}

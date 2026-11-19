#include "tunbridge/tun.hpp"
#include "tunbridge/config.hpp"
#include "tunbridge/net.hpp"
#include "tunbridge/system.hpp"

// --- TUN движок и загрузка с SHA-256 ---
static void url_encode(const char* s, char* d, int dsz) {
    static const char hx[] = "0123456789ABCDEF"; int j = 0;
    for (int i = 0; s[i] && j < dsz - 4; i++) {
        unsigned char c = (unsigned char)s[i];
        if ((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='-'||c=='_'||c=='.'||c=='~') d[j++] = (char)c;
        else { d[j++] = '%'; d[j++] = hx[c>>4]; d[j++] = hx[c&15]; }
    }
    if (dsz > 0) d[j < dsz ? j : dsz - 1] = 0;
}
static void SanitizeWArg(const wchar_t* s, wchar_t* d, size_t n) {
    size_t j = 0;
    for (size_t i = 0; s[i] && j + 1 < n; i++) if (s[i] != L'"' && s[i] != L'\r' && s[i] != L'\n') d[j++] = s[i];
    if (n) d[j] = 0;
}
static bool GetAdapterFriendlyNameByIndex(DWORD idx, wchar_t* out, int maxCh) {
    out[0] = 0; PIP_ADAPTER_ADDRESSES a = AllocAdapters(); if (!a) return false;
    bool ok = false;
    for (auto p = a; p; p = p->Next) if (p->IfIndex == idx && p->FriendlyName) { SafeCopyW(out, (size_t)maxCh, p->FriendlyName); ok = true; break; }
    free(a); return ok;
}
static DWORD FindIpIfIndex(const char* ipStr, bool reqPref) {
    struct in_addr tg; if (inet_pton(AF_INET, ipStr, &tg) != 1) return 0;
    if (reqPref) {
        PIP_ADAPTER_ADDRESSES a = AllocAdapters(); if (!a) return 0;
        DWORD idx = 0;
        for (auto p = a; p && !idx; p = p->Next) {
            if (p->OperStatus != IfOperStatusUp) continue;
            for (auto u = p->FirstUnicastAddress; u; u = u->Next) {
                if (u->Address.lpSockaddr && u->Address.lpSockaddr->sa_family == AF_INET &&
                    ((struct sockaddr_in*)u->Address.lpSockaddr)->sin_addr.s_addr == tg.s_addr &&
                    u->DadState == IpDadStatePreferred) { idx = p->IfIndex; break; }
            }
        }
        free(a); return idx;
    }
    ULONG sz = 0; GetIpAddrTable(nullptr, &sz, FALSE); if (!sz) return 0;
    auto t = (PMIB_IPADDRTABLE)malloc(sz); if (!t) return 0;
    DWORD idx = 0;
    if (GetIpAddrTable(t, &sz, FALSE) == NO_ERROR)
        for (DWORD i = 0; i < t->dwNumEntries; i++) if (t->table[i].dwAddr == tg.s_addr) { idx = t->table[i].dwIndex; break; }
    free(t); return idx;
}
static DWORD WINAPI TunLogReaderThread(LPVOID param) {
    HANDLE hp = (HANDLE)param; char buf[512]; DWORD br = 0;
    while (ReadFile(hp, buf, sizeof(buf) - 1, &br, nullptr) && br > 0) {
        buf[br] = 0; EnterCriticalSection(&g_logCs); SafeCopyA(g_tunLastErr, sizeof(g_tunLastErr), buf); LeaveCriticalSection(&g_logCs);
    }
    CloseHandle(hp); return 0;
}
void StopTunEngine() {
    RunHiddenWait(L"route delete 0.0.0.0 mask 128.0.0.0", 3000);
    RunHiddenWait(L"route delete 128.0.0.0 mask 128.0.0.0", 3000);
    if (g_addedPhoneRouteIp[0]) {
        if (IsSafeHostString(g_addedPhoneRouteIp)) {
            wchar_t c[256]; _snwprintf(c, 255, L"route delete %hs mask 255.255.255.255", g_addedPhoneRouteIp); c[255] = 0;
            RunHiddenWait(c, 3000);
        }
        g_addedPhoneRouteIp[0] = 0; SaveLastPhoneRouteIp(nullptr);
    } else CleanupSavedPhoneRouteFromReg();

    if (g_tunProc)      { TerminateProcess(g_tunProc, 0); WaitForSingleObject(g_tunProc, 2000); CloseHandle(g_tunProc); g_tunProc = nullptr; }
    if (g_tunLogThread) { WaitForSingleObject(g_tunLogThread, 1000); CloseHandle(g_tunLogThread); g_tunLogThread = nullptr; }
    if (g_tunJob)       { CloseHandle(g_tunJob); g_tunJob = nullptr; }
    CleanupOrphanedTunProcesses();
    g_tunIfIndex = 0; g_hasPrevOctets = false;
    RunHiddenWait(L"ipconfig /flushdns", 3000);
}
DWORD WINAPI StartTunThread(LPVOID) {
    InterlockedIncrement(&g_workerThreads);
    auto Fail = [&](LPARAM code) {
        InterlockedExchange(&g_busy, 0);
        if (!g_shuttingDown && g_hwnd) PostMessageW(g_hwnd, WM_APP_TUN_DONE, 0, code);
        InterlockedDecrement(&g_workerThreads);
    };
    wchar_t tunExe[MAX_PATH] = {}, wintunDll[MAX_PATH] = {};
    if (!FindTunBinaries(tunExe, wintunDll)) { Fail(1); return 0; }

    NetConfig cfg; GetNetConfig(&cfg);
    if (!IsSafeHostString(cfg.ip)) { Fail(11); return 0; }

    int proto = 1, preErr = TestUpstreamAuthAndProto(&cfg, &proto);
    if (preErr != 0) { Fail(10 + preErr); return 0; }
    InterlockedExchange(&g_upstreamProto, proto);

    CleanupOrphanedTunProcesses();
    RunHiddenWait(L"route delete 0.0.0.0 mask 128.0.0.0", 2000);
    RunHiddenWait(L"route delete 128.0.0.0 mask 128.0.0.0", 2000);
    CleanupSavedPhoneRouteFromReg();

    EnterCriticalSection(&g_logCs); g_tunLastErr[0] = 0; LeaveCriticalSection(&g_logCs);

    DWORD phAddr = inet_addr(cfg.ip); char resIp[64] = {};
    if (phAddr == INADDR_NONE) {
        struct addrinfo h = {}, *r = nullptr; h.ai_family = AF_INET;
        if (getaddrinfo(cfg.ip, nullptr, &h, &r) == 0 && r) {
            phAddr = ((struct sockaddr_in*)r->ai_addr)->sin_addr.s_addr;
            inet_ntop(AF_INET, &((struct sockaddr_in*)r->ai_addr)->sin_addr, resIp, sizeof(resIp));
            freeaddrinfo(r);
        }
    } else SafeCopyA(resIp, sizeof(resIp), cfg.ip);

    MIB_IPFORWARDROW pr = {}; char origGw[64] = {}; wchar_t ifName[256] = {}, safeIf[256] = {};
    bool needBypass = false;
    if (phAddr != INADDR_NONE && GetBestRoute(phAddr, 0, &pr) == NO_ERROR) {
        if (pr.dwForwardNextHop) { struct in_addr g; g.s_addr = pr.dwForwardNextHop; inet_ntop(AF_INET, &g, origGw, sizeof(origGw)); }
        GetAdapterFriendlyNameByIndex(pr.dwForwardIfIndex, ifName, 256);
        if (_wcsnicmp(ifName, L"TunBridge", 9) == 0 || wcsstr(ifName, L"Cloudflare")) ifName[0] = 0;
        if (pr.dwForwardType == 4 && origGw[0]) needBypass = true;
    }
    SanitizeWArg(ifName, safeIf, 256);

    char eu[780] = {}, ep[780] = {}, url[2048] = {};
    const char* sch = (proto == 2) ? "http" : "socks5";
    if (cfg.user[0] || cfg.pass[0]) {
        url_encode(cfg.user, eu, sizeof(eu)); url_encode(cfg.pass, ep, sizeof(ep));
        snprintf(url, sizeof(url), "%s://%s:%s@%s:%d", sch, eu, ep, cfg.ip, cfg.socksPort);
    } else snprintf(url, sizeof(url), "%s://%s:%d", sch, cfg.ip, cfg.socksPort);

    wchar_t cmd[3072];
    if (safeIf[0]) _snwprintf(cmd, 3071, L"\"%s\" --device tun://TunBridge --proxy \"%hs\" --interface \"%s\" --loglevel error", tunExe, url, safeIf);
    else           _snwprintf(cmd, 3071, L"\"%s\" --device tun://TunBridge --proxy \"%hs\" --loglevel error", tunExe, url);
    cmd[3071] = 0;

    SECURITY_ATTRIBUTES sa = { sizeof(sa), nullptr, TRUE };
    HANDLE hr = nullptr, hw = nullptr;
    if (CreatePipe(&hr, &hw, &sa, 0)) SetHandleInformation(hr, HANDLE_FLAG_INHERIT, 0);

    g_tunJob = CreateJobObjectW(nullptr, nullptr);
    if (g_tunJob) {
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION je = {}; je.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        SetInformationJobObject(g_tunJob, JobObjectExtendedLimitInformation, &je, sizeof(je));
    }
    STARTUPINFOW si = { sizeof(si) }; si.dwFlags = STARTF_USESHOWWINDOW | (hw ? STARTF_USESTDHANDLES : 0);
    si.wShowWindow = SW_HIDE; si.hStdOutput = hw; si.hStdError = hw;
    PROCESS_INFORMATION pi = {};
    if (!CreateProcessW(nullptr, cmd, nullptr, nullptr, hw ? TRUE : FALSE, CREATE_NO_WINDOW | CREATE_SUSPENDED, nullptr, g_exeDir, &si, &pi)) {
        if (hw) CloseHandle(hw);
        if (hr) CloseHandle(hr);
        if (g_tunJob) { CloseHandle(g_tunJob); g_tunJob = nullptr; }
        Fail(2); return 0;
    }
    if (hw) CloseHandle(hw);
    if (hr) g_tunLogThread = CreateThread(nullptr, 32768, TunLogReaderThread, hr, 0, nullptr);
    if (g_tunJob) AssignProcessToJobObject(g_tunJob, pi.hProcess);
    ResumeThread(pi.hThread); CloseHandle(pi.hThread); g_tunProc = pi.hProcess;

    bool netOk = false;
    for (int i = 0; i < 32 && !g_shuttingDown; i++) {
        if (WaitForSingleObject(g_tunProc, 0) != WAIT_TIMEOUT) break;
        if (RunHiddenWait(L"netsh interface ipv4 set address name=\"TunBridge\" source=static addr=10.251.251.1 mask=255.255.255.0", 3000) == 0) { netOk = true; break; }
        Sleep(250);
    }
    if (!netOk || g_shuttingDown) { Sleep(100); StopTunEngine(); Fail(3); return 0; }

    RunHiddenWait(L"netsh interface ipv4 set interface interface=\"TunBridge\" metric=5", 3000);
    RunHiddenWait(L"netsh interface ipv4 set dnsservers name=\"TunBridge\" static address=1.1.1.1 register=none validate=no", 3000);
    RunHiddenWait(L"netsh interface ipv4 add dnsservers name=\"TunBridge\" address=8.8.8.8 index=2 validate=no", 3000);

    DWORD ifIdx = 0;
    for (int i = 0; i < 20 && !ifIdx && !g_shuttingDown; i++) { ifIdx = FindIpIfIndex("10.251.251.1", i < 14); if (!ifIdx) Sleep(200); }
    if (!ifIdx || g_shuttingDown) { StopTunEngine(); Fail(4); return 0; }

    g_tunIfIndex = ifIdx; g_hasPrevOctets = false;
    if (needBypass && IsSafeHostString(resIp) && IsSafeHostString(origGw)) {
        wchar_t rc[256]; _snwprintf(rc, 255, L"route add %hs mask 255.255.255.255 %hs metric 1", resIp, origGw); rc[255] = 0;
        if (RunHiddenWait(rc, 3000) == 0) { SafeCopyA(g_addedPhoneRouteIp, sizeof(g_addedPhoneRouteIp), resIp); SaveLastPhoneRouteIp(resIp); }
    }
    wchar_t r1[256], r2[256];
    _snwprintf(r1, 255, L"route add 0.0.0.0 mask 128.0.0.0 10.251.251.1 metric 1 if %lu", ifIdx); r1[255] = 0;
    _snwprintf(r2, 255, L"route add 128.0.0.0 mask 128.0.0.0 10.251.251.1 metric 1 if %lu", ifIdx); r2[255] = 0;
    bool rOk = false;
    for (int i = 0; i < 6 && !g_shuttingDown; i++) { if (RunHiddenWait(r1, 3000) == 0 && RunHiddenWait(r2, 3000) == 0) { rOk = true; break; } Sleep(300); }
    if (!rOk || g_shuttingDown) { StopTunEngine(); Fail(4); return 0; }

    RunHiddenWait(L"ipconfig /flushdns", 3000);
    InterlockedExchange(&g_busy, 0);
    if (!g_shuttingDown && g_hwnd) PostMessageW(g_hwnd, WM_APP_TUN_DONE, 1, 0);
    InterlockedDecrement(&g_workerThreads); return 0;
}
DWORD WINAPI DownloadTunThread(LPVOID) {
    InterlockedIncrement(&g_workerThreads);
    const wchar_t* ps =
        L"powershell -NoProfile -ExecutionPolicy Bypass -Command \""
        L"$ErrorActionPreference='Stop'; [Net.ServicePointManager]::SecurityProtocol='Tls12'; "
        L"$tmp=Join-Path $PWD '_dl_tmp'; Remove-Item $tmp -Recurse -Force -EA 0; New-Item -ItemType Directory -Path $tmp | Out-Null; "
        L"try { "
        L"  $wz=Join-Path $tmp 'w.zip'; $wd=Join-Path $tmp 'w'; "
        L"  Invoke-WebRequest 'https://www.wintun.net/builds/wintun-0.14.1.zip' -OutFile $wz -UseBasicParsing; "
        L"  if ((Get-FileHash $wz -Algorithm SHA256).Hash -ne '07C256185D6EE3652E09FA55C0B673E2624B565E02C4B9091C79CA7D2F24EF51') { throw 'wzip' }; "
        L"  Expand-Archive $wz $wd -Force; $dll=Join-Path $wd 'wintun\\bin\\amd64\\wintun.dll'; "
        L"  if ((Get-FileHash $dll -Algorithm SHA256).Hash -ne 'E5DA8447DC2C320EDC0FC52FA01885C103DE8C118481F683643CACC3220DAFCE') { throw 'wdll' }; "
        L"  if ((Get-AuthenticodeSignature $dll).Status -ne 'Valid') { throw 'wsig' }; "
        L"  $u='https://github.com/xjasonlyu/tun2socks/releases/download/v2.7.0/tun2socks-windows-amd64.zip'; "
        L"  $h='C5D46E9452F6C9CC7C15AB9158D6D6A0169CEECD6BCA019CE476B49337D2BE43'; "
        L"  try { "
        L"    $r=Invoke-RestMethod -Uri 'https://api.github.com/repos/xjasonlyu/tun2socks/releases/latest' -Headers @{'User-Agent'='TunBridge'} -TimeoutSec 10; "
        L"    $a=$r.assets | Where-Object { $_.name -eq 'tun2socks-windows-amd64.zip' } | Select-Object -First 1; "
        L"    if ($a -and $a.browser_download_url -like 'https://github.com/xjasonlyu/tun2socks/releases/download/*' -and $a.digest -match '^sha256:([0-9a-fA-F]{64})$') { "
        L"      $u=$a.browser_download_url; $h=$matches[1].ToUpper() "
        L"    } "
        L"  } catch {}; "
        L"  $tz=Join-Path $tmp 't.zip'; $td=Join-Path $tmp 't'; "
        L"  Invoke-WebRequest $u -OutFile $tz -UseBasicParsing; "
        L"  if ((Get-FileHash $tz -Algorithm SHA256).Hash -ne $h) { throw 'tzip' }; "
        L"  Expand-Archive $tz $td -Force; "
        L"  $ex=Get-ChildItem $td -Filter '*.exe' -Recurse | Select-Object -First 1; if (-not $ex) { throw 'texe' }; "
        L"  Copy-Item $dll 'wintun.dll' -Force; Copy-Item $ex.FullName 'tun2socks.exe' -Force "
        L"} finally { Remove-Item $tmp -Recurse -Force -EA 0 }\"";

    CleanupOrphanedTunProcesses();
    DWORD code = RunHiddenWait(ps, 120000);
    wchar_t t1[MAX_PATH], t2[MAX_PATH]; char sha[65] = {};
    bool ok = (code == 0) && FindTunBinaries(t1, t2) && ComputeFileSha256Hex(t2, sha) && _stricmp(sha, WINTUN_DLL_SHA256) == 0;
    InterlockedExchange(&g_busy, 0);
    if (!g_shuttingDown && g_hwnd) PostMessageW(g_hwnd, WM_APP_DL_DONE, ok ? 1 : 0, 0);
    InterlockedDecrement(&g_workerThreads); return 0;
}

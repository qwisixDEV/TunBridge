#include "tunbridge/probe.hpp"
#include "tunbridge/net.hpp"
#include "tunbridge/config.hpp"

// --- Сканер и тест связи ---
static bool CheckProxyOnConnectedSocket(SOCKET s, DWORD ipH, int port) {
    u_long b = 0; ioctlsocket(s, FIONBIO, &b);
    DWORD t = 1500; setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&t, sizeof(t)); setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&t, sizeof(t));
    unsigned char hi[4] = { 5, 2, 0, 2 }, rp[4] = {};
    if (send_all(s, (const char*)hi, 4) && recv_exact(s, (char*)rp, 2) && rp[0] == 5) return true;
    if (rp[0] == 'H' && rp[1] == 'T') {
        struct sockaddr_in sa = {}; sa.sin_family = AF_INET; sa.sin_addr.s_addr = htonl(ipH); sa.sin_port = htons((unsigned short)port);
        SOCKET hs = connect_tcp_sa((struct sockaddr*)&sa, sizeof(sa), AF_INET, 1500);
        if (hs != INVALID_SOCKET) {
            const char* rq = "CONNECT cp.cloudflare.com:80 HTTP/1.1\r\nHost: cp.cloudflare.com:80\r\n\r\n";
            char rb[1024] = {}; int rl = 0;
            bool ok = send_all(hs, rq, (int)strlen(rq)) && recv_http_headers(hs, rb, sizeof(rb), &rl);
            closesocket(hs);
            if (ok && (!_strnicmp(rb, "HTTP/1.1 200", 12) || !_strnicmp(rb, "HTTP/1.0 200", 12) || strstr(rb, "Proxy-Authenticate:") || strstr(rb, "proxy-authenticate:"))) return true;
        }
    }
    return false;
}
static bool ProbeProxyPort(DWORD ipH, int port, DWORD ms) {
    struct sockaddr_in sa = {}; sa.sin_family = AF_INET; sa.sin_addr.s_addr = htonl(ipH); sa.sin_port = htons((unsigned short)port);
    SOCKET s = connect_tcp_sa((struct sockaddr*)&sa, sizeof(sa), AF_INET, ms);
    if (s == INVALID_SOCKET) return false;
    bool ok = CheckProxyOnConnectedSocket(s, ipH, port); closesocket(s); return ok;
}
DWORD WINAPI ScanThread(LPVOID param) {
    InterlockedIncrement(&g_workerThreads);
    int port = (int)(INT_PTR)param; DWORD found = 0;
    NetConfig cfg; GetNetConfig(&cfg);
    if (cfg.ip[0]) { struct in_addr a; if (inet_pton(AF_INET, cfg.ip, &a) == 1 && ProbeProxyPort(ntohl(a.s_addr), port, 1200)) found = a.s_addr; }

    MIB_IPFORWARDROW bd = {}; DWORD defIf = 0;
    if (GetBestRoute(inet_addr("8.8.8.8"), 0, &bd) == NO_ERROR) {
        defIf = bd.dwForwardIfIndex;
        if (!found && bd.dwForwardNextHop && ProbeProxyPort(ntohl(bd.dwForwardNextHop), port, 1200)) found = bd.dwForwardNextHop;
    }
    if (!found && !g_shuttingDown) {
        PIP_ADAPTER_ADDRESSES a = AllocAdapters();
        struct Sub { DWORD pref, own; int prio; } list[16] = {}; int cnt = 0;
        if (a) {
            for (auto p = a; p && cnt < 16; p = p->Next) {
                if (p->OperStatus != IfOperStatusUp || p->IfType == IF_TYPE_SOFTWARE_LOOPBACK || p->IfType == IF_TYPE_TUNNEL) continue;
                if (p->FriendlyName && (_wcsnicmp(p->FriendlyName, L"TunBridge", 9) == 0 || wcsstr(p->FriendlyName, L"Cloudflare"))) continue;
                for (auto u = p->FirstUnicastAddress; u && cnt < 16; u = u->Next) {
                    if (!u->Address.lpSockaddr || u->Address.lpSockaddr->sa_family != AF_INET) continue;
                    DWORD ipH = ntohl(((struct sockaddr_in*)u->Address.lpSockaddr)->sin_addr.s_addr);
                    BYTE b1 = (BYTE)(ipH >> 24), b2 = (BYTE)((ipH >> 16) & 255);
                    if (b1 == 127 || (b1 == 169 && b2 == 254) || (ipH & 0xFFFFFF00) == 0x0AFBFB00) continue;
                    DWORD pref = ipH & 0xFFFFFF00; bool dup = false;
                    for (int i = 0; i < cnt; i++) if (list[i].pref == pref) dup = true;
                    if (!dup) list[cnt++] = { pref, ipH, p->IfIndex == defIf ? 0 : (b1 == 192 && b2 == 168 ? 1 : 2) };
                }
            }
            free(a);
        }
        for (int ps = 0; ps <= 2 && !found && !g_shuttingDown; ps++)
            for (int ix = 0; ix < cnt && !found && !g_shuttingDown; ix++) {
                if (list[ix].prio != ps) continue;
                const int B = 32;
                for (int base = 1; base <= 254 && !found && !g_shuttingDown; base += B) {
                    SOCKET ss[B]; DWORD ips[B]; int n = 0;
                    for (int k = 0; k < B && base + k <= 254; k++) {
                        DWORD c = list[ix].pref | (DWORD)(base + k); if (c == list[ix].own) continue;
                        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); if (s == INVALID_SOCKET) continue;
                        u_long nb = 1; ioctlsocket(s, FIONBIO, &nb);
                        struct sockaddr_in sa = {}; sa.sin_family = AF_INET; sa.sin_addr.s_addr = htonl(c); sa.sin_port = htons((unsigned short)port);
                        connect(s, (struct sockaddr*)&sa, sizeof(sa)); ss[n] = s; ips[n] = c; n++;
                    }
                    ULONGLONG t0 = GetTickCount64();
                    while (n > 0 && !found && !g_shuttingDown) {
                        ULONGLONG el = GetTickCount64() - t0; if (el >= 900) break;
                        fd_set wf, ef; FD_ZERO(&wf); FD_ZERO(&ef);
                        for (int i = 0; i < n; i++) { FD_SET(ss[i], &wf); FD_SET(ss[i], &ef); }
                        struct timeval tv = { 0, (long)((900 - el) * 1000) };
                        if (select(0, nullptr, &wf, &ef, &tv) <= 0) break;
                        for (int i = n - 1; i >= 0; i--) {
                            bool w = FD_ISSET(ss[i], &wf) != 0, e = FD_ISSET(ss[i], &ef) != 0;
                            if (w || e) {
                                int err = 1, eln = sizeof(err); if (w) getsockopt(ss[i], SOL_SOCKET, SO_ERROR, (char*)&err, &eln);
                                SOCKET sd = ss[i]; DWORD ic = ips[i]; ss[i] = ss[n-1]; ips[i] = ips[n-1]; n--;
                                if (w && err == 0 && CheckProxyOnConnectedSocket(sd, ic, port)) { closesocket(sd); found = htonl(ic); break; }
                                closesocket(sd);
                            }
                        }
                    }
                    for (int i = 0; i < n; i++) closesocket(ss[i]);
                }
            }
    }
    InterlockedExchange(&g_scanning, 0);
    if (!g_shuttingDown && g_hwnd) PostMessageW(g_hwnd, WM_APP_SCAN_DONE, found ? 1 : 0, (LPARAM)found);
    InterlockedDecrement(&g_workerThreads); return 0;
}
static DWORD WINAPI ProbeThread(LPVOID param) {
    InterlockedIncrement(&g_workerThreads);
    ProbeResult* pr = (ProbeResult*)param;
    int err = 0, ms = 0, proto = 1; char cc[4] = {};
    NetConfig cfg; GetNetConfig(&cfg);

    SOCKET s = connect_via_upstream(&cfg, "cp.cloudflare.com", 80, &err, &proto);
    if (!err && s != INVALID_SOCKET) {
        InterlockedExchange(&g_upstreamProto, proto);
        DWORD t = 4500; int nd = 1;
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&t, sizeof(t));
        setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&t, sizeof(t));
        setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (const char*)&nd, sizeof(nd));
        LARGE_INTEGER fq, t0, t1; QueryPerformanceFrequency(&fq);
        const char* hq = "HEAD /generate_204 HTTP/1.1\r\nHost: cp.cloudflare.com\r\nConnection: keep-alive\r\n\r\n";
        int hl = (int)strlen(hq), rl = 0; char rb[1024];
        QueryPerformanceCounter(&t0);
        if (send_all(s, hq, hl) && recv_http_headers(s, rb, sizeof(rb), &rl)) {
            QueryPerformanceCounter(&t1);
            ms = (int)(((t1.QuadPart - t0.QuadPart) * 1000LL) / fq.QuadPart); if (ms < 1) ms = 1; if (ms > 9999) ms = 9999;
            if (!strstr(rb, "close") && !strstr(rb, "Close")) {
                char rb2[1024]; int rl2 = 0; QueryPerformanceCounter(&t0);
                if (send_all(s, hq, hl) && recv_http_headers(s, rb2, sizeof(rb2), &rl2)) {
                    QueryPerformanceCounter(&t1);
                    ms = (int)(((t1.QuadPart - t0.QuadPart) * 1000LL) / fq.QuadPart); if (ms < 1) ms = 1; if (ms > 9999) ms = 9999;
                    const char* tr = "GET /cdn-cgi/trace HTTP/1.1\r\nHost: cp.cloudflare.com\r\nUser-Agent: TunBridge/1.0\r\nConnection: close\r\n\r\n";
                    if (send_all(s, tr, (int)strlen(tr))) {
                        char tb[2048]; int tot = 0;
                        while (tot < (int)sizeof(tb) - 1) { int n = recv(s, tb + tot, (int)sizeof(tb) - 1 - tot, 0); if (n <= 0) break; tot += n; }
                        tb[tot] = 0; const char* p = strstr(tb, "loc=");
                        if (p && p[4]>='A' && p[4]<='Z' && p[5]>='A' && p[5]<='Z' && (!p[6]||p[6]=='\r'||p[6]=='\n'||p[6]==' ')) { cc[0]=p[4]; cc[1]=p[5]; }
                    }
                }
            }
        } else err = 4;
        closesocket(s);
    }
    if (!err && !cc[0] && !g_shuttingDown) {
        SOCKET gs = connect_via_upstream(&cfg, "ip-api.com", 80, nullptr, nullptr);
        if (gs != INVALID_SOCKET) {
            DWORD t = 3000; setsockopt(gs, SOL_SOCKET, SO_RCVTIMEO, (const char*)&t, sizeof(t)); setsockopt(gs, SOL_SOCKET, SO_SNDTIMEO, (const char*)&t, sizeof(t));
            const char* gq = "GET /line/?fields=countryCode HTTP/1.0\r\nHost: ip-api.com\r\nUser-Agent: TunBridge/1.0\r\nConnection: close\r\n\r\n";
            if (send_all(gs, gq, (int)strlen(gq))) {
                char b[1024]; int tot = 0;
                while (tot < (int)sizeof(b) - 1) { int n = recv(gs, b + tot, (int)sizeof(b) - 1 - tot, 0); if (n <= 0) break; tot += n; }
                b[tot] = 0; char* bd = strstr(b, "200 OK") ? strstr(b, "\r\n\r\n") : nullptr;
                if (bd) { bd += 4; while (*bd == ' ' || *bd == '\r' || *bd == '\n' || *bd == '\t') bd++;
                    if (bd[0]>='A'&&bd[0]<='Z'&&bd[1]>='A'&&bd[1]<='Z'&&(!bd[2]||bd[2]=='\r'||bd[2]=='\n'||bd[2]==' ')) { cc[0]=bd[0]; cc[1]=bd[1]; } }
            }
            closesocket(gs);
        }
    }
    pr->err = err; pr->pingMs = ms; pr->proto = proto; memcpy(pr->cc, cc, 4);
    if (pr->fromTestBtn) InterlockedExchange(&g_testing, 0);
    if (g_shuttingDown || !g_hwnd || !PostMessageW(g_hwnd, WM_APP_PROBE_DONE, 0, (LPARAM)pr)) free(pr);
    InterlockedDecrement(&g_workerThreads); return 0;
}
void LaunchProbeAsync(bool fromBtn) {
    auto pr = (ProbeResult*)calloc(1, sizeof(ProbeResult));
    if (!pr) { if (fromBtn) InterlockedExchange(&g_testing, 0); return; }
    pr->gen = g_connGen; pr->fromTestBtn = fromBtn;
    HANDLE ht = CreateThread(nullptr, 0, ProbeThread, pr, 0, nullptr);
    if (ht) CloseHandle(ht); else { free(pr); if (fromBtn) InterlockedExchange(&g_testing, 0); }
}

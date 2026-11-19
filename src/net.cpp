#include "tunbridge/net.hpp"
#include "tunbridge/config.hpp"

// --- Сеть: SOCKS5 / HTTP CONNECT + локальный мост ---
static void Base64Encode(const unsigned char* in, size_t len, char* out, size_t outSz) {
    static const char tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t j = 0;
    for (size_t i = 0; i < len && j + 4 < outSz; i += 3) {
        size_t rem = len - i;
        unsigned v = ((unsigned)in[i] << 16) | ((rem > 1 ? (unsigned)in[i+1] : 0u) << 8) | (rem > 2 ? (unsigned)in[i+2] : 0u);
        out[j++] = tbl[(v >> 18) & 63]; out[j++] = tbl[(v >> 12) & 63];
        out[j++] = (rem > 1) ? tbl[(v >> 6) & 63] : '='; out[j++] = (rem > 2) ? tbl[v & 63] : '=';
    }
    if (outSz) out[j < outSz ? j : outSz - 1] = 0;
}
bool send_all(SOCKET s, const char* d, int len) {
    for (int st = 0; st < len;) { int n = send(s, d + st, len - st, 0); if (n <= 0) return false; st += n; }
    return true;
}
bool recv_exact(SOCKET s, char* b, int len) {
    for (int g = 0; g < len;) { int n = recv(s, b + g, len - g, 0); if (n <= 0) return false; g += n; }
    return true;
}
bool recv_http_headers(SOCKET s, char* b, int sz, int* outLen) {
    int tot = 0;
    while (tot < sz - 1) {
        int n = recv(s, b + tot, sz - 1 - tot, 0); if (n <= 0) break;
        tot += n; b[tot] = 0; if (strstr(b, "\r\n\r\n")) { *outLen = tot; return true; }
    }
    *outLen = tot; return false;
}
SOCKET connect_tcp_sa(const struct sockaddr* sa, int salen, int fam, DWORD ms) {
    SOCKET s = socket(fam, SOCK_STREAM, IPPROTO_TCP); if (s == INVALID_SOCKET) return INVALID_SOCKET;
    u_long nb = 1; ioctlsocket(s, FIONBIO, &nb);
    int r = connect(s, sa, salen);
    if (r == SOCKET_ERROR && WSAGetLastError() != WSAEWOULDBLOCK) { closesocket(s); return INVALID_SOCKET; }
    if (r != 0) {
        fd_set wf, ef; FD_ZERO(&wf); FD_ZERO(&ef); FD_SET(s, &wf); FD_SET(s, &ef);
        struct timeval tv = { (long)(ms / 1000), (long)((ms % 1000) * 1000) };
        int err = 1, el = sizeof(err);
        if (select(0, nullptr, &wf, &ef, &tv) <= 0 || !FD_ISSET(s, &wf) || getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&err, &el) != 0 || err != 0) {
            closesocket(s); return INVALID_SOCKET;
        }
    }
    nb = 0; ioctlsocket(s, FIONBIO, &nb);
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&ms, sizeof(ms));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&ms, sizeof(ms));
    return s;
}
static SOCKET connect_tcp(const char* host, int port, DWORD ms) {
    struct in_addr v4;
    if (inet_pton(AF_INET, host, &v4) == 1) {
        struct sockaddr_in sa = {}; sa.sin_family = AF_INET; sa.sin_addr = v4; sa.sin_port = htons((unsigned short)port);
        return connect_tcp_sa((struct sockaddr*)&sa, sizeof(sa), AF_INET, ms);
    }
    char ps[16]; snprintf(ps, sizeof(ps), "%d", port);
    struct addrinfo h = {}, *res = nullptr; h.ai_family = AF_UNSPEC; h.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, ps, &h, &res) != 0 || !res) return INVALID_SOCKET;
    SOCKET s = INVALID_SOCKET;
    for (auto p = res; p; p = p->ai_next) { s = connect_tcp_sa(p->ai_addr, (int)p->ai_addrlen, p->ai_family, ms); if (s != INVALID_SOCKET) break; }
    freeaddrinfo(res); return s;
}
static SOCKET connect_via_http_proxy(const NetConfig* c, const char* host, unsigned short port, int* outErr) {
    if (outErr) *outErr = 0;
    SOCKET s = connect_tcp(c->ip, c->socksPort, 4000);
    if (s == INVALID_SOCKET) { if (outErr) *outErr = 1; return INVALID_SOCKET; }
    char authHdr[1024] = {};
    if (c->user[0] || c->pass[0]) {
        char creds[540], b64[800] = {}; snprintf(creds, sizeof(creds), "%s:%s", c->user, c->pass);
        Base64Encode((const unsigned char*)creds, strlen(creds), b64, sizeof(b64));
        snprintf(authHdr, sizeof(authHdr), "Proxy-Authorization: Basic %s\r\n", b64);
    }
    char req[1600];
    int rl = snprintf(req, sizeof(req), "CONNECT %s:%u HTTP/1.1\r\nHost: %s:%u\r\n%sProxy-Connection: keep-alive\r\n\r\n",
                      host, (unsigned)port, host, (unsigned)port, authHdr);
    char resp[2048]; int respLen = 0;
    if (rl <= 0 || rl >= (int)sizeof(req) || !send_all(s, req, rl) || !recv_http_headers(s, resp, sizeof(resp), &respLen) || _strnicmp(resp, "HTTP/1.", 7) != 0) {
        closesocket(s); if (outErr) *outErr = 2; return INVALID_SOCKET;
    }
    const char* sp = strchr(resp, ' '); int code = sp ? atoi(sp + 1) : 0;
    if (code == 407) { closesocket(s); if (outErr) *outErr = 3; return INVALID_SOCKET; }
    if (code < 200 || code >= 300) { closesocket(s); if (outErr) *outErr = 4; return INVALID_SOCKET; }
    DWORD z = 0; setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&z, sizeof(z)); setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&z, sizeof(z));
    return s;
}
static SOCKET connect_via_socks5_cfg(const NetConfig* c, const char* host, unsigned short port, int* outErr) {
    if (outErr) *outErr = 0;
    SOCKET s = connect_tcp(c->ip, c->socksPort, 4000);
    if (s == INVALID_SOCKET) { if (outErr) *outErr = 1; return INVALID_SOCKET; }
    bool ha = (c->user[0] || c->pass[0]);
    unsigned char hi[4] = { 5, (unsigned char)(ha ? 2 : 1), 0, 2 }, rp[4] = {};
    if (!send_all(s, (const char*)hi, ha ? 4 : 3) || !recv_exact(s, (char*)rp, 2) || rp[0] != 5) {
        closesocket(s); if (outErr) *outErr = 2; return INVALID_SOCKET;
    }
    if (rp[1] == 2) {
        int ul = (int)strlen(c->user), pl = (int)strlen(c->pass); if (ul > 255) ul = 255; if (pl > 255) pl = 255;
        unsigned char a[520]; a[0] = 1; a[1] = (unsigned char)ul; memcpy(a + 2, c->user, ul);
        a[2 + ul] = (unsigned char)pl; memcpy(a + 3 + ul, c->pass, pl);
        if (!send_all(s, (const char*)a, 3 + ul + pl) || !recv_exact(s, (char*)rp, 2) || rp[1] != 0) {
            closesocket(s); if (outErr) *outErr = 3; return INVALID_SOCKET;
        }
    } else if (rp[1] != 0) { closesocket(s); if (outErr) *outErr = 3; return INVALID_SOCKET; }

    unsigned char rq[300]; int rl = 0; struct in_addr v4;
    if (inet_pton(AF_INET, host, &v4) == 1) {
        rq[0]=5; rq[1]=1; rq[2]=0; rq[3]=1; memcpy(rq+4, &v4, 4); rq[8]=port>>8; rq[9]=port&255; rl=10;
    } else {
        int hl = (int)strlen(host); if (hl <= 0 || hl > 255) { closesocket(s); if (outErr) *outErr = 4; return INVALID_SOCKET; }
        rq[0]=5; rq[1]=1; rq[2]=0; rq[3]=3; rq[4]=(unsigned char)hl; memcpy(rq+5, host, hl); rq[5+hl]=port>>8; rq[6+hl]=port&255; rl=7+hl;
    }
    if (!send_all(s, (const char*)rq, rl) || !recv_exact(s, (char*)rp, 4) || rp[0] != 5 || rp[1] != 0) {
        closesocket(s); if (outErr) *outErr = 4; return INVALID_SOCKET;
    }
    char dmp[300]; unsigned char dl = 0;
    if ((rp[3]==1 && !recv_exact(s, dmp, 6)) ||
        (rp[3]==3 && (!recv_exact(s, (char*)&dl, 1) || !recv_exact(s, dmp, dl + 2))) ||
        (rp[3]==4 && !recv_exact(s, dmp, 18))) { closesocket(s); return INVALID_SOCKET; }
    DWORD z = 0; setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&z, sizeof(z)); setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&z, sizeof(z));
    return s;
}
SOCKET connect_via_upstream(const NetConfig* c, const char* host, unsigned short port, int* outErr, int* outProto) {
    LONG pr = InterlockedCompareExchange(&g_upstreamProto, 0, 0);
    int err = 0; SOCKET s = INVALID_SOCKET;
    if (pr == 2) {
        s = connect_via_http_proxy(c, host, port, &err);
        if (s != INVALID_SOCKET) { if (outProto) *outProto = 2; if (outErr) *outErr = 0; return s; }
        if (err == 2) { s = connect_via_socks5_cfg(c, host, port, &err); if (s != INVALID_SOCKET && outProto) *outProto = 1; }
    } else {
        s = connect_via_socks5_cfg(c, host, port, &err);
        if (s != INVALID_SOCKET) { if (outProto) *outProto = 1; if (outErr) *outErr = 0; return s; }
        if (err == 2) { s = connect_via_http_proxy(c, host, port, &err); if (s != INVALID_SOCKET && outProto) *outProto = 2; }
    }
    if (outErr) *outErr = err;
    return s;
}
int TestUpstreamAuthAndProto(const NetConfig* c, int* outProto) {
    *outProto = 1;
    SOCKET s = connect_tcp(c->ip, c->socksPort, 2500);
    if (s == INVALID_SOCKET) return 1;
    bool ha = (c->user[0] || c->pass[0]);
    unsigned char hi[4] = { 5, (unsigned char)(ha ? 2 : 1), 0, 2 }, rp[2] = {};
    if (send_all(s, (const char*)hi, ha ? 4 : 3) && recv_exact(s, (char*)rp, 2) && rp[0] == 5) {
        if (rp[1] == 2) {
            int ul = (int)strlen(c->user), pl = (int)strlen(c->pass); if (ul > 255) ul = 255; if (pl > 255) pl = 255;
            unsigned char a[520]; a[0]=1; a[1]=(unsigned char)ul; memcpy(a+2, c->user, ul);
            a[2+ul]=(unsigned char)pl; memcpy(a+3+ul, c->pass, pl);
            if (!send_all(s, (const char*)a, 3 + ul + pl) || !recv_exact(s, (char*)rp, 2) || rp[1] != 0) { closesocket(s); return 3; }
        } else if (rp[1] != 0) { closesocket(s); return 3; }
        closesocket(s); *outProto = 1; return 0;
    }
    closesocket(s);
    int he = 0; SOCKET hs = connect_via_http_proxy(c, "cp.cloudflare.com", 80, &he);
    if (hs != INVALID_SOCKET) { closesocket(hs); *outProto = 2; return 0; }
    return he ? he : 2;
}
static void relay_sockets(SOCKET a, SOCKET b) {
    char buf[32768]; int nd = 1;
    setsockopt(a, IPPROTO_TCP, TCP_NODELAY, (const char*)&nd, sizeof(nd));
    setsockopt(b, IPPROTO_TCP, TCP_NODELAY, (const char*)&nd, sizeof(nd));
    while (g_running && g_mode == 0 && !g_shuttingDown) {
        fd_set fds; FD_ZERO(&fds); FD_SET(a, &fds); FD_SET(b, &fds);
        struct timeval tv = { 1, 0 }; int r = select(0, &fds, nullptr, nullptr, &tv);
        if (r < 0) break;
        if (r == 0) continue;
        if (FD_ISSET(a, &fds)) { int n = recv(a, buf, sizeof(buf), 0); if (n <= 0 || !send_all(b, buf, n)) break; InterlockedExchangeAdd64(&g_bytesTotal, n); }
        if (FD_ISSET(b, &fds)) { int n = recv(b, buf, sizeof(buf), 0); if (n <= 0 || !send_all(a, buf, n)) break; InterlockedExchangeAdd64(&g_bytesTotal, n); }
    }
}
static void parse_host_port(const char* src, char* host, int hsz, unsigned short* port, unsigned short defP) {
    *port = defP; host[0] = 0;
    if (src[0] == '[') {
        const char* e = strchr(src + 1, ']');
        if (e) {
            int l = (int)(e - (src + 1)); if (l >= hsz) l = hsz - 1;
            memcpy(host, src + 1, l); host[l] = 0;
            if (e[1] == ':') *port = (unsigned short)atoi(e + 2);
            return;
        }
    }
    const char* c = strrchr(src, ':');
    if (c) {
        int l = (int)(c - src); if (l >= hsz) l = hsz - 1;
        memcpy(host, src, l); host[l] = 0; int p = atoi(c + 1); if (p > 0 && p <= 65535) *port = (unsigned short)p;
    } else SafeCopyA(host, (size_t)hsz, src);
}
SOCKET BindLocalProxyPort(int pref, int* outPort) {
    for (int i = 0; i <= 32; i++) {
        int port = (i == 32) ? 0 : ((i == 0) ? pref : pref + i);
        if (i < 32 && (port < 1025 || port > 65000)) port = 10000 + (i % 5000);
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); if (s == INVALID_SOCKET) return INVALID_SOCKET;
        int ex = 1; setsockopt(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (const char*)&ex, sizeof(ex));
        struct sockaddr_in a = {}; a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK); a.sin_port = htons((unsigned short)port);
        if (bind(s, (struct sockaddr*)&a, sizeof(a)) == 0 && listen(s, SOMAXCONN) == 0) {
            int al = sizeof(a);
            if (port == 0 && getsockname(s, (struct sockaddr*)&a, &al) == 0) port = (int)ntohs(a.sin_port);
            if (port > 0) { *outPort = port; return s; }
        }
        closesocket(s);
    }
    return INVALID_SOCKET;
}
static DWORD WINAPI ClientThread(LPVOID param) {
    InterlockedIncrement(&g_workerThreads); InterlockedIncrement(&g_activeConns);
    SOCKET cs = (SOCKET)(ULONG_PTR)param, rs = INVALID_SOCKET;
    NetConfig cfg; GetNetConfig(&cfg);
    char req[16384]; int tot = 0; char* hdrEnd = nullptr;
    DWORD to = 8000; setsockopt(cs, SOL_SOCKET, SO_RCVTIMEO, (const char*)&to, sizeof(to));
    while (tot < (int)sizeof(req) - 1) {
        int n = recv(cs, req + tot, (int)sizeof(req) - 1 - tot, 0); if (n <= 0) break;
        tot += n; req[tot] = 0; hdrEnd = strstr(req, "\r\n\r\n"); if (hdrEnd) break;
    }
    if (!hdrEnd) goto done;
    to = 0; setsockopt(cs, SOL_SOCKET, SO_RCVTIMEO, (const char*)&to, sizeof(to));
    {
        char* le = strstr(req, "\r\n"); if (!le) goto done;
        char fl[2048]; int fln = (int)(le - req); if (fln >= (int)sizeof(fl)) fln = (int)sizeof(fl) - 1;
        memcpy(fl, req, fln); fl[fln] = 0;
        char meth[32] = {}, uri[1536] = {}, ver[32] = {};
        if (sscanf(fl, "%31s %1535s %31s", meth, uri, ver) < 2) goto done;
        if (!ver[0]) SafeCopyA(ver, sizeof(ver), "HTTP/1.1");
        char host[256] = {}; unsigned short port = 443;

        if (_stricmp(meth, "CONNECT") == 0) {
            parse_host_port(uri, host, sizeof(host), &port, 443); if (!host[0]) goto done;
            rs = connect_via_upstream(&cfg, host, port, nullptr, nullptr);
            if (rs == INVALID_SOCKET) { const char* e = "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n"; send_all(cs, e, (int)strlen(e)); goto done; }
            const char* ok = "HTTP/1.1 200 Connection Established\r\n\r\n";
            if (send_all(cs, ok, (int)strlen(ok))) relay_sockets(cs, rs);
            goto done;
        }
        const char* path = "/"; char hp[256] = {};
        if (_strnicmp(uri, "http://", 7) == 0) {
            const char* p = uri + 7, *sl = strchr(p, '/');
            int hl = sl ? (int)(sl - p) : (int)strlen(p); if (hl >= (int)sizeof(hp)) hl = (int)sizeof(hp) - 1;
            memcpy(hp, p, hl); hp[hl] = 0; if (sl) path = sl;
            parse_host_port(hp, host, sizeof(host), &port, 80);
        } else {
            path = uri;
            for (const char* cur = le + 2; cur < hdrEnd;) {
                const char* nx = strstr(cur, "\r\n"); if (!nx || nx > hdrEnd) break;
                if (nx - cur > 5 && _strnicmp(cur, "Host:", 5) == 0) {
                    const char* v = cur + 5; while (v < nx && (*v == ' ' || *v == '\t')) v++;
                    int l = (int)(nx - v); if (l >= (int)sizeof(hp)) l = (int)sizeof(hp) - 1;
                    memcpy(hp, v, l); hp[l] = 0; parse_host_port(hp, host, sizeof(host), &port, 80); break;
                }
                cur = nx + 2;
            }
        }
        if (!host[0]) goto done;
        rs = connect_via_upstream(&cfg, host, port, nullptr, nullptr);
        if (rs == INVALID_SOCKET) { const char* e = "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n"; send_all(cs, e, (int)strlen(e)); goto done; }

        char out[16384]; int ol = snprintf(out, sizeof(out), "%s %s %s\r\n", meth, path, ver);
        if (ol <= 0 || ol >= (int)sizeof(out) - 64) goto done;
        for (const char* cur = le + 2; cur < hdrEnd && ol < (int)sizeof(out) - 64;) {
            const char* nx = strstr(cur, "\r\n"); if (!nx || nx > hdrEnd) break;
            int ll = (int)(nx - cur);
            if (ll > 0 && _strnicmp(cur, "Proxy-Connection:", 17) && _strnicmp(cur, "Proxy-Authorization:", 20) && _strnicmp(cur, "Connection:", 11)) {
                if (ol + ll + 2 < (int)sizeof(out) - 32) { memcpy(out + ol, cur, ll); ol += ll; out[ol++] = '\r'; out[ol++] = '\n'; }
            }
            cur = nx + 2;
        }
        int tl = snprintf(out + ol, sizeof(out) - ol, "Connection: close\r\n\r\n");
        if (tl <= 0 || ol + tl >= (int)sizeof(out)) goto done;
        ol += tl;
        if (send_all(rs, out, ol)) {
            int bo = (int)((hdrEnd + 4) - req);
            if (tot <= bo || send_all(rs, req + bo, tot - bo)) relay_sockets(cs, rs);
        }
    }
done:
    if (rs != INVALID_SOCKET) closesocket(rs);
    if (cs != INVALID_SOCKET) closesocket(cs);
    InterlockedDecrement(&g_activeConns); InterlockedDecrement(&g_workerThreads); return 0;
}
DWORD WINAPI ServerThread(LPVOID) {
    InterlockedIncrement(&g_workerThreads);
    while (g_running && g_mode == 0 && !g_shuttingDown) {
        SOCKET c = accept(g_listenSock, nullptr, nullptr); if (c == INVALID_SOCKET) break;
        HANDLE ht = CreateThread(nullptr, 0, ClientThread, (LPVOID)(ULONG_PTR)c, 0, nullptr);
        if (ht) CloseHandle(ht); else closesocket(c);
    }
    InterlockedDecrement(&g_workerThreads); return 0;
}

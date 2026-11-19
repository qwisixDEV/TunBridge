#pragma once

#include "tunbridge/common.hpp"

bool send_all(SOCKET s, const char* d, int len);
bool recv_exact(SOCKET s, char* b, int len);
bool recv_http_headers(SOCKET s, char* b, int sz, int* outLen);
SOCKET connect_tcp_sa(const struct sockaddr* sa, int salen, int fam, DWORD ms);
SOCKET connect_via_upstream(const NetConfig* c, const char* host, unsigned short port, int* outErr, int* outProto);
int TestUpstreamAuthAndProto(const NetConfig* c, int* outProto);
SOCKET BindLocalProxyPort(int pref, int* outPort);
DWORD WINAPI ServerThread(LPVOID);

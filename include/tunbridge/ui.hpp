#pragma once

#include "tunbridge/common.hpp"

HICON MakeAppIcon(int sz, bool active);
void ResizeWindowClient(HWND hwnd, int cw, int ch);
void SetErrorMsg(const wchar_t* msg);
void UpdateTray();
LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp);

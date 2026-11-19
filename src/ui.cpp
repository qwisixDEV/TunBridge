#include "tunbridge/ui.hpp"
#include "tunbridge/app.hpp"
#include "tunbridge/config.hpp"
#include "tunbridge/probe.hpp"
#include "tunbridge/system.hpp"

// --- Шрифты ---
static int CALLBACK EnumFontCb(const LOGFONTW*, const TEXTMETRICW*, DWORD, LPARAM lp) { *(bool*)lp = true; return 0; }
static bool IsFontAvailable(const wchar_t* name) {
    bool found = false; HDC hdc = GetDC(nullptr); LOGFONTW lf = {}; lf.lfCharSet = DEFAULT_CHARSET;
    SafeCopyW(lf.lfFaceName, LF_FACESIZE, name); EnumFontFamiliesExW(hdc, &lf, EnumFontCb, (LPARAM)&found, 0);
    ReleaseDC(nullptr, hdc); return found;
}
static bool FontHasGlyph(HFONT f, wchar_t ch) {
    HDC hdc = GetDC(nullptr); HGDIOBJ o = SelectObject(hdc, f); WORD idx = 0xFFFF;
    DWORD r = GetGlyphIndicesW(hdc, &ch, 1, &idx, GGI_MARK_NONEXISTING_GLYPHS);
    SelectObject(hdc, o); ReleaseDC(nullptr, hdc); return r != GDI_ERROR && idx != 0xFFFF;
}
static HFONT MkFont(int px, int wt, DWORD pitch, const wchar_t* face) {
    return CreateFontW(S(px), 0, 0, 0, wt, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                       CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, pitch, face);
}

// --- Иконки, тема, трей ---
HICON MakeAppIcon(int sz, bool active) {
    Gdiplus::Bitmap bmp(sz, sz, PixelFormat32bppARGB);
    Gdiplus::Graphics g(&bmp); g.SetSmoothingMode(Gdiplus::SmoothingModeAntiAlias); g.Clear(Gdiplus::Color(0,0,0,0));
    float f = (float)sz / 32.0f, pad = sz <= 16 ? 0.5f : 1.5f * f, w = (float)sz - pad * 2.0f, r = sz <= 16 ? 3.5f : 7.0f * f, d = r * 2.0f;
    Gdiplus::GraphicsPath sq;
    sq.AddArc(pad, pad, d, d, 180, 90); sq.AddArc(pad + w - d, pad, d, d, 270, 90);
    sq.AddArc(pad + w - d, pad + w - d, d, d, 0, 90); sq.AddArc(pad, pad + w - d, d, d, 90, 90); sq.CloseFigure();
    Gdiplus::SolidBrush brBg(Gdiplus::Color(255,34,34,34));
    Gdiplus::Pen penBrd(active ? Gdiplus::Color(255,58,76,68) : Gdiplus::Color(255,62,62,62), 1.0f);
    g.FillPath(&brBg, &sq); g.DrawPath(&penBrd, &sq);
    float l = 9.5f * f, rt = 22.5f * f, top = 9.0f * f, my = 15.5f * f, bot = 22.0f * f;
    Gdiplus::GraphicsPath arch;
    arch.AddLine(l, bot, l, my); arch.AddArc(l, top, rt - l, (my - top) * 2.0f, 180, 180); arch.AddLine(rt, my, rt, bot);
    Gdiplus::Pen pA(active ? Gdiplus::Color(255,240,244,242) : Gdiplus::Color(255,145,145,145), sz <= 16 ? 1.8f : 2.8f * f);
    pA.SetStartCap(Gdiplus::LineCapRound); pA.SetEndCap(Gdiplus::LineCapRound); pA.SetLineJoin(Gdiplus::LineJoinRound);
    g.DrawPath(&pA, &arch);
    float dd = sz <= 16 ? 4.2f : 6.4f * f;
    Gdiplus::SolidBrush brDot(active ? GCol(COL_ACCENT) : Gdiplus::Color(255,108,108,108));
    g.FillEllipse(&brDot, 16.0f * f - dd * 0.5f, 18.0f * f - dd * 0.5f, dd, dd);
    HICON hi = nullptr; bmp.GetHICON(&hi); return hi;
}
static void ApplyDwmTheme(HWND hwnd) {
    HMODULE h = LoadLibraryW(L"dwmapi.dll"); if (!h) return;
    auto fn = (HRESULT(WINAPI*)(HWND,DWORD,LPCVOID,DWORD))GetProcAddress(h, "DwmSetWindowAttribute");
    if (fn) {
        BOOL dark = TRUE; if (FAILED(fn(hwnd, 20, &dark, sizeof(dark)))) fn(hwnd, 19, &dark, sizeof(dark));
        COLORREF cap = COL_BG, brd = COL_BORDER; fn(hwnd, 35, &cap, sizeof(cap)); fn(hwnd, 34, &brd, sizeof(brd));
    }
    FreeLibrary(h);
}
void ResizeWindowClient(HWND hwnd, int cw, int ch) {
    RECT rc = { 0, 0, S(cw), S(ch) };
    AdjustWindowRectEx(&rc, (DWORD)GetWindowLongPtrW(hwnd, GWL_STYLE), FALSE, (DWORD)GetWindowLongPtrW(hwnd, GWL_EXSTYLE));
    SetWindowPos(hwnd, nullptr, 0, 0, rc.right - rc.left, rc.bottom - rc.top, SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE);
}
void SetErrorMsg(const wchar_t* msg) {
    g_hasError = (msg && msg[0]);
    SafeCopyW(g_errMsg, 192, g_hasError ? msg : L"");
    if (g_hwnd) InvalidateRect(g_hwnd, nullptr, FALSE);
}
void UpdateTray() {
    if (!g_trayAdded) return;
    g_nid.hIcon = g_running ? g_trayIconOn : g_trayIconOff;
    if (g_running && g_countryCode[0] && g_pingMs >= 0)
        _snwprintf(g_nid.szTip, 127, L"TunBridge · %hs · %d мс", g_countryCode, g_pingMs);
    else
        _snwprintf(g_nid.szTip, 127, L"TunBridge — %s", g_running ? (g_mode ? L"Подключено (TUN)" : L"Подключено (Прокси)") : L"Отключено");
    g_nid.szTip[127] = 0; Shell_NotifyIconW(NIM_MODIFY, &g_nid);
}

// --- Отрисовка ---
static void FillRoundRectAA(Gdiplus::Graphics& g, float x, float y, float w, float h, float r, Gdiplus::Color fl, Gdiplus::Color bd, bool drawBd = true) {
    Gdiplus::GraphicsPath p; float d = r * 2.0f;
    p.AddArc(x, y, d, d, 180, 90); p.AddArc(x + w - d, y, d, d, 270, 90);
    p.AddArc(x + w - d, y + h - d, d, d, 0, 90); p.AddArc(x, y + h - d, d, d, 90, 90); p.CloseFigure();
    Gdiplus::SolidBrush br(fl); g.FillPath(&br, &p);
    if (drawBd) { Gdiplus::Pen pn(bd, 1.0f); g.DrawPath(&pn, &p); }
}
static void DrawTxt(HDC hdc, HFONT f, COLORREF c, const wchar_t* t, int x, int y, int w, int h, UINT fmt) {
    SelectObject(hdc, f); SetTextColor(hdc, c); RECT rc = { x, y, x + w, y + h }; DrawTextW(hdc, t, -1, &rc, fmt);
}
static void DrawTelemetry(HDC hdc, Gdiplus::Graphics& gp, int x, int y, int w, int h) {
    bool on = g_running != 0, busy = g_busy != 0;
    COLORREF dot = RGB(105,105,105); wchar_t txt[220] = {};
    if (busy) { dot = COL_MUTED; SafeCopyW(txt, 220, g_mode ? L"Настройка адаптера TunBridge..." : L"Загрузка драйвера TUN..."); }
    else if (on) {
        double mb = (double)g_bytesTotal / (1024.0 * 1024.0);
        if (g_pingMs == -2) { dot = COL_DANGER; _snwprintf(txt, 219, L"Нет выхода в сеть через прокси · %.2f МБ", mb); }
        else {
            dot = COL_ACCENT;
            if (g_countryCode[0] && g_pingMs >= 0) _snwprintf(txt, 219, L"Подключено · %hs · %d мс · %.2f МБ", g_countryCode, g_pingMs, mb);
            else if (g_pingMs >= 0) _snwprintf(txt, 219, L"Подключено · %d мс · %.2f МБ", g_pingMs, mb);
            else if (g_mode) _snwprintf(txt, 219, L"Подключено · TunBridge · %.2f МБ", mb);
            else _snwprintf(txt, 219, L"Подключено · 127.0.0.1:%d · %.2f МБ", g_cfg.localPort, mb);
        }
    } else if (g_hasError) { dot = COL_DANGER; SafeCopyW(txt, 220, g_errMsg); }
    else SafeCopyW(txt, 220, g_mode ? L"Отключено · Весь трафик (TUN)" : L"Отключено · Системный прокси");
    txt[219] = 0;

    SelectObject(hdc, g_fontSmall); SIZE sz = {}; GetTextExtentPoint32W(hdc, txt, (int)wcslen(txt), &sz);
    int ds = S(8), gp8 = S(8), tw = sz.cx < (w - ds - gp8) ? sz.cx : (w - ds - gp8), sx = x + (w - (ds + gp8 + tw)) / 2;
    Gdiplus::SolidBrush br(GCol(dot)); gp.FillEllipse(&br, (float)sx, (float)(y + (h - ds) / 2), (float)ds, (float)ds);
    SetTextColor(hdc, on ? COL_TEXT : COL_MUTED);
    RECT rc = { sx + ds + gp8, y, x + w, y + h }; DrawTextW(hdc, txt, -1, &rc, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
}
static void PaintWindow(HWND hwnd, HDC hdcOut) {
    RECT rc; GetClientRect(hwnd, &rc); int W = rc.right, H = rc.bottom; if (W <= 0 || H <= 0) return;
    HDC hdc = CreateCompatibleDC(hdcOut); HBITMAP hbm = CreateCompatibleBitmap(hdcOut, W, H);
    if (!hdc || !hbm) { if (hbm) DeleteObject(hbm); if (hdc) DeleteDC(hdc); return; }
    HGDIOBJ ob = SelectObject(hdc, hbm);
    HBRUSH bg = CreateSolidBrush(COL_BG); FillRect(hdc, &rc, bg); DeleteObject(bg); SetBkMode(hdc, TRANSPARENT);
    Gdiplus::Graphics gp(hdc); gp.SetSmoothingMode(Gdiplus::SmoothingModeAntiAlias);

    if (g_screen == 0) DrawTxt(hdc, g_fontTitle, COL_TEXT, L"TunBridge", S(24), S(16), S(224), S(32), DT_LEFT|DT_VCENTER|DT_SINGLELINE);
    else               DrawTxt(hdc, g_fontTitle, COL_TEXT, L"Настройки",   S(64), S(16), S(240), S(32), DT_LEFT|DT_VCENTER|DT_SINGLELINE);
    Gdiplus::Pen dv(GCol(COL_BORDER), 1.0f); gp.DrawLine(&dv, (float)S(24), (float)S(56), (float)S(336), (float)S(56));

    bool lk = g_running || g_busy;
    auto Box = [&](int id, int x, int y, int w, int h) {
        FillRoundRectAA(gp, (float)S(x), (float)S(y), (float)S(w), (float)S(h), (float)S(6),
                        GCol(lk ? COL_SURFACE_RO : COL_SURFACE), GCol(!lk && g_focusedEditId == id ? COL_BORDER_FOC : COL_BORDER), true);
    };
    if (g_screen == 0) {
        FillRoundRectAA(gp, (float)S(24), (float)S(72), (float)S(312), (float)S(40), (float)S(8), GCol(COL_SURFACE), GCol(COL_BORDER));
        DrawTxt(hdc, g_fontSmall, COL_MUTED, L"IP телефона / прокси", S(24), S(136), S(132), S(16), DT_LEFT|DT_SINGLELINE);
        if (g_ipLabelState || g_scanning || g_testing) {
            COLORREF c = (!g_scanning && !g_testing) ? (g_ipLabelState == 1 ? COL_ACCENT : (g_ipLabelState < 0 ? COL_DANGER : COL_MUTED)) : COL_MUTED;
            DrawTxt(hdc, g_fontSmall, c, g_ipLabelText, S(156), S(136), S(180), S(16), DT_RIGHT|DT_SINGLELINE);
        }
        Box(ID_EDIT_IP, 24, 160, 232, 32);
        FillRoundRectAA(gp, (float)S(24), (float)S(224), (float)S(312), (float)S(136), (float)S(8), GCol(COL_SURFACE), GCol(COL_BORDER));
        DrawTelemetry(hdc, gp, S(32), S(308), S(296), S(24));
    } else {
        DrawTxt(hdc, g_fontSmall, COL_MUTED, L"Порт прокси",        S(24),  S(68),  S(152), S(16), DT_LEFT|DT_SINGLELINE);
        DrawTxt(hdc, g_fontSmall, COL_MUTED, L"Локальный порт",     S(184), S(68),  S(152), S(16), DT_LEFT|DT_SINGLELINE);
        Box(ID_EDIT_SPORT, 24, 88, 152, 30); Box(ID_EDIT_LPORT, 184, 88, 152, 30);
        DrawTxt(hdc, g_fontSmall, COL_MUTED, L"Логин (если нужен)", S(24),  S(130), S(312), S(16), DT_LEFT|DT_SINGLELINE);
        Box(ID_EDIT_USER, 24, 150, 312, 30);
        DrawTxt(hdc, g_fontSmall, COL_MUTED, L"Пароль (если нужен)",S(24),  S(192), S(312), S(16), DT_LEFT|DT_SINGLELINE);
        Box(ID_EDIT_PASS, 24, 212, 312, 30);
        gp.DrawLine(&dv, (float)S(24), (float)S(258), (float)S(336), (float)S(258));

        DrawTxt(hdc, g_fontBody, COL_TEXT, L"Сворачивать в трей", S(24), S(272), S(240), S(32), DT_LEFT|DT_VCENTER|DT_SINGLELINE);
        DrawTxt(hdc, g_fontBody, COL_TEXT, L"Автозапуск в трей",  S(24), S(308), S(240), S(32), DT_LEFT|DT_VCENTER|DT_SINGLELINE);
        DrawTxt(hdc, g_fontBody, COL_TEXT, L"Автовозврат Zapret", S(24), S(344), S(240), S(32), DT_LEFT|DT_VCENTER|DT_SINGLELINE);

        wchar_t t1[MAX_PATH], t2[MAX_PATH]; bool ht = FindTunBinaries(t1, t2);
        DrawTxt(hdc, g_fontBody,  COL_TEXT, ht ? L"Драйвер TUN" : L"Драйвер TUN", S(24), S(384), S(160), S(32), DT_LEFT|DT_VCENTER|DT_SINGLELINE);
        DrawTxt(hdc, g_fontSmall, ht ? COL_MUTED : COL_DANGER, ht ? L"Установлен" : L"Не найден", S(188), S(384), S(108), S(32), DT_RIGHT|DT_VCENTER|DT_SINGLELINE);
        DrawTxt(hdc, g_fontBody,  COL_TEXT, L"Обход DPI (Zapret)", S(24), S(422), S(160), S(32), DT_LEFT|DT_VCENTER|DT_SINGLELINE);
        DrawTxt(hdc, g_fontSmall, g_zapretActive ? COL_DANGER : COL_MUTED, g_zapretActive ? L"Активен" : L"Остановлен", S(188), S(422), S(108), S(32), DT_RIGHT|DT_VCENTER|DT_SINGLELINE);
    }
    BitBlt(hdcOut, 0, 0, W, H, hdc, 0, 0, SRCCOPY);
    SelectObject(hdc, ob); DeleteObject(hbm); DeleteDC(hdc);
}
static void DrawOwnerButton(DRAWITEMSTRUCT* dis) {
    int w = dis->rcItem.right - dis->rcItem.left, h = dis->rcItem.bottom - dis->rcItem.top; if (w <= 0 || h <= 0) return;
    bool pr = (dis->itemState & ODS_SELECTED) != 0, ds = (dis->itemState & ODS_DISABLED) != 0;
    bool hv = !ds && GetWindowLongPtrW(dis->hwndItem, GWLP_USERDATA) != 0;
    HDC hm = CreateCompatibleDC(dis->hDC); HBITMAP bm = CreateCompatibleBitmap(dis->hDC, w, h);
    if (!hm || !bm) { if (bm) DeleteObject(bm); if (hm) DeleteDC(hm); return; }
    HGDIOBJ ob = SelectObject(hm, bm);

    UINT id = dis->CtlID;
    COLORREF pbg = (id==ID_BTN_MODE_PROXY||id==ID_BTN_MODE_TUN||id==ID_BTN_TOGGLE) ? COL_SURFACE
                 : (id==ID_BTN_SHOWPASS ? ((g_running||g_busy) ? COL_SURFACE_RO : COL_SURFACE) : COL_BG);
    RECT rf = { 0, 0, w, h }; HBRUSH br = CreateSolidBrush(pbg); FillRect(hm, &rf, br); DeleteObject(br);
    Gdiplus::Graphics gp(hm); gp.SetSmoothingMode(Gdiplus::SmoothingModeAntiAlias); SetBkMode(hm, TRANSPARENT);

    if (id == ID_BTN_SHOWPASS) {
        if (pr || hv) FillRoundRectAA(gp, 0.5f, 0.5f, w - 1.5f, h - 1.5f, (float)S(4), GCol(pr ? COL_SURFACE_PR : COL_SURFACE_HV), GCol(COL_BORDER), false);
        wchar_t gl[2] = { g_passVisible ? g_glyphEyeOff : (wchar_t)0xE7B3, 0 };
        SelectObject(hm, g_fontIcon); SetTextColor(hm, hv ? COL_TEXT : COL_MUTED); DrawTextW(hm, gl, 1, &rf, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
    } else if (id == ID_BTN_TRAY_OPT || id == ID_BTN_AUTOSTART || id == ID_BTN_AUTO_ZAPRET) {
        bool on = (id == ID_BTN_TRAY_OPT) ? (g_minimizeToTray != 0) : (id == ID_BTN_AUTOSTART ? g_autoStart : (g_autoRestoreZapret != 0));
        FillRoundRectAA(gp, 1, 1, w - 2.0f, h - 2.0f, h * 0.5f - 1.0f,
                        GCol(on ? (hv ? RGB(92,92,92) : RGB(78,78,78)) : (hv ? COL_SURFACE_HV : COL_SURFACE)), GCol(on ? RGB(106,106,106) : COL_MUTED));
        float ts = h - 8.0f; Gdiplus::SolidBrush bt(GCol(on ? COL_TEXT : COL_MUTED));
        gp.FillEllipse(&bt, on ? (w - ts - 4.0f) : 4.0f, 4.0f, ts, ts);
    } else if (id == ID_BTN_MODE_PROXY || id == ID_BTN_MODE_TUN) {
        bool sel = (id == ID_BTN_MODE_PROXY && g_mode == 0) || (id == ID_BTN_MODE_TUN && g_mode == 1);
        if (sel) FillRoundRectAA(gp, 0.5f, 0.5f, w - 1.5f, h - 1.5f, (float)S(6), GCol(hv ? RGB(60,60,60) : COL_SEG_ACTIVE), GCol(RGB(68,68,68)));
        else if (hv || pr) FillRoundRectAA(gp, 0.5f, 0.5f, w - 1.5f, h - 1.5f, (float)S(6), GCol(pr ? COL_SURFACE_PR : COL_SURFACE_HV), GCol(COL_BORDER), false);
        wchar_t t[64] = {}; GetWindowTextW(dis->hwndItem, t, 63);
        SelectObject(hm, sel ? g_fontSegSemi : g_fontSeg); SetTextColor(hm, ds && !sel ? RGB(100,100,100) : (sel ? COL_TEXT : COL_MUTED));
        DrawTextW(hm, t, -1, &rf, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
    } else if (id == ID_BTN_TOGGLE) {
        COLORREF fl = g_busy ? COL_BORDER : (g_running ? (pr ? COL_DANGER_PR : (hv ? COL_DANGER_HV : COL_DANGER)) : (pr ? COL_ACCENT_PR : (hv ? COL_ACCENT_HV : COL_ACCENT)));
        COLORREF fg = g_busy ? COL_MUTED : (g_running ? COL_TEXT : RGB(12,20,16));
        FillRoundRectAA(gp, 0.5f, 0.5f, w - 1.5f, h - 1.5f, (float)S(6), GCol(fl), GCol(fl), false);
        wchar_t t[64] = {}; GetWindowTextW(dis->hwndItem, t, 63);
        SelectObject(hm, g_fontSemi); SetTextColor(hm, fg); DrawTextW(hm, t, -1, &rf, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
    } else {
        bool hdr = (id == ID_BTN_TRAY_WIN || id == ID_BTN_SETTINGS || id == ID_BTN_BACK);
        if (!hdr || hv || pr) FillRoundRectAA(gp, 0.5f, 0.5f, w - 1.5f, h - 1.5f, (float)S(6),
            GCol(hdr ? (pr ? COL_SURFACE_PR : COL_SURFACE) : (pr ? COL_SURFACE_PR : (hv ? COL_SURFACE_HV : COL_SURFACE))), GCol(COL_BORDER), !hdr);
        wchar_t gl[2] = {}; COLORREF fg = ds ? RGB(130,130,130) : (hv ? COL_TEXT : COL_ICON_IDLE);
        if (id == ID_BTN_TRAY_WIN)       { gl[0] = 0xE73F; fg = hv ? COL_TEXT : COL_MUTED; }
        else if (id == ID_BTN_SETTINGS)  { gl[0] = 0xE713; fg = hv ? COL_TEXT : COL_MUTED; }
        else if (id == ID_BTN_BACK)      { gl[0] = 0xE72B; }
        else if (id == ID_BTN_SCAN)      { gl[0] = g_scanning ? 0xE72C : 0xE721; }
        else if (id == ID_BTN_DL_TUN)    { gl[0] = 0xE896; }
        else if (id == ID_BTN_STOP_ZAPRET) { gl[0] = g_glyphStop; fg = ds ? RGB(105,105,105) : COL_DANGER; }
        else if (id == ID_BTN_TEST) {
            if (g_testing) { gl[0] = 0xE72C; fg = COL_MUTED; }
            else if (g_testIconState == 1) { gl[0] = 0xE73E; fg = COL_ACCENT; }
            else if (g_testIconState < 0)  { gl[0] = 0xE711; fg = COL_DANGER; }
            else gl[0] = 0xE945;
        }
        SelectObject(hm, g_fontIcon); SetTextColor(hm, fg); DrawTextW(hm, gl, 1, &rf, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
    }
    BitBlt(dis->hDC, 0, 0, w, h, hm, 0, 0, SRCCOPY);
    SelectObject(hm, ob); DeleteObject(bm); DeleteDC(hm);
}
static LRESULT CALLBACK BtnSubProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    if (msg == WM_MOUSEMOVE && !GetWindowLongPtrW(hwnd, GWLP_USERDATA) && IsWindowEnabled(hwnd)) {
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, 1); TRACKMOUSEEVENT t = { sizeof(t), TME_LEAVE, hwnd, 0 }; TrackMouseEvent(&t); InvalidateRect(hwnd, nullptr, FALSE);
    } else if (msg == WM_MOUSELEAVE && GetWindowLongPtrW(hwnd, GWLP_USERDATA)) {
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0); InvalidateRect(hwnd, nullptr, FALSE);
    } else if ((msg == WM_SHOWWINDOW || msg == WM_ENABLE) && !wp) {
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
    } else if (msg == WM_SETCURSOR && IsWindowEnabled(hwnd)) { SetCursor(LoadCursor(nullptr, IDC_HAND)); return TRUE; }
    return CallWindowProcW(g_origBtnProc, hwnd, msg, wp, lp);
}
static HWND MakeEdit(HWND p, const char* t, int id, int x, int y, int w, int h, int th, int rpad = 8, bool pw = false) {
    int py = (S(h) - th) / 2; if (py < 2) py = 2;
    HWND hw = CreateWindowExA(0, "EDIT", t, WS_VISIBLE|WS_CHILD|WS_TABSTOP|ES_AUTOHSCROLL|(pw ? ES_PASSWORD : 0),
                              S(x) + S(8), S(y) + py, S(w) - S(8) - S(rpad), th + 2, p, (HMENU)(INT_PTR)id, nullptr, nullptr);
    SendMessageW(hw, WM_SETFONT, (WPARAM)g_fontMono, TRUE);
    SendMessageW(hw, EM_SETMARGINS, EC_LEFTMARGIN|EC_RIGHTMARGIN, MAKELPARAM(2, 2)); return hw;
}
static HWND MakeBtn(HWND p, const wchar_t* t, int id, int x, int y, int w, int h, const wchar_t* tip = nullptr) {
    HWND hw = CreateWindowW(L"BUTTON", t, WS_VISIBLE|WS_CHILD|WS_TABSTOP|BS_OWNERDRAW, S(x), S(y), S(w), S(h), p, (HMENU)(INT_PTR)id, nullptr, nullptr);
    WNDPROC pv = (WNDPROC)SetWindowLongPtrW(hw, GWLP_WNDPROC, (LONG_PTR)BtnSubProc); if (!g_origBtnProc) g_origBtnProc = pv;
    if (tip && g_tooltip) {
        TOOLINFOW ti = { sizeof(ti), TTF_IDISHWND|TTF_SUBCLASS, g_hwnd, (UINT_PTR)hw, {}, nullptr, (LPWSTR)tip };
        SendMessageW(g_tooltip, TTM_ADDTOOLW, 0, (LPARAM)&ti);
    }
    return hw;
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
        case WM_CREATE: {
            g_hwnd = hwnd; ApplyDwmTheme(hwnd);
            if (IsFontAvailable(L"Segoe UI Variable Text")) SafeCopyW(g_uiFontName, 64, L"Segoe UI Variable Text");
            if (IsFontAvailable(L"Cascadia Mono"))          SafeCopyW(g_monoFontName, 64, L"Cascadia Mono");
            if (IsFontAvailable(L"Segoe Fluent Icons"))     SafeCopyW(g_iconFontName, 64, L"Segoe Fluent Icons");

            g_fontTitle = MkFont(20, FW_SEMIBOLD, DEFAULT_PITCH|FF_SWISS, g_uiFontName);
            g_fontSemi  = MkFont(14, FW_SEMIBOLD, DEFAULT_PITCH|FF_SWISS, g_uiFontName);
            g_fontBody  = MkFont(14, FW_NORMAL,   DEFAULT_PITCH|FF_SWISS, g_uiFontName);
            g_fontSegSemi = MkFont(13, FW_SEMIBOLD, DEFAULT_PITCH|FF_SWISS, g_uiFontName);
            g_fontSeg   = MkFont(13, FW_NORMAL,   DEFAULT_PITCH|FF_SWISS, g_uiFontName);
            g_fontSmall = MkFont(12, FW_NORMAL,   DEFAULT_PITCH|FF_SWISS, g_uiFontName);
            g_fontMono  = MkFont(14, FW_NORMAL,   FIXED_PITCH|FF_MODERN,  g_monoFontName);
            g_fontIcon  = MkFont(16, FW_NORMAL,   DEFAULT_PITCH,          g_iconFontName);
            g_glyphEyeOff = FontHasGlyph(g_fontIcon, 0xED1A) ? 0xED1A : 0xE7B3;
            g_glyphStop   = FontHasGlyph(g_fontIcon, 0xE71A) ? 0xE71A : 0xE711;
            g_brInput = CreateSolidBrush(COL_SURFACE); g_brInputRo = CreateSolidBrush(COL_SURFACE_RO);

            HDC hd = GetDC(hwnd); SelectObject(hd, g_fontMono); TEXTMETRICW tm = {}; GetTextMetricsW(hd, &tm); ReleaseDC(hwnd, hd);
            g_tooltip = CreateWindowExW(WS_EX_TOPMOST, TOOLTIPS_CLASSW, nullptr, WS_POPUP|TTS_ALWAYSTIP|TTS_NOPREFIX,
                                        CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, hwnd, nullptr, nullptr, nullptr);
            if (g_tooltip) SendMessageW(g_tooltip, TTM_SETMAXTIPWIDTH, 0, 300);

            hBtnTrayWin  = MakeBtn(hwnd, L"", ID_BTN_TRAY_WIN, 264, 16, 32, 32, L"Свернуть в трей");
            hBtnSettings = MakeBtn(hwnd, L"", ID_BTN_SETTINGS, 304, 16, 32, 32, L"Настройки");
            hBtnBack     = MakeBtn(hwnd, L"", ID_BTN_BACK,      24, 16, 32, 32, L"Назад");
            hBtnModeProxy = MakeBtn(hwnd, L"Системный прокси",  ID_BTN_MODE_PROXY,  28, 76, 150, 32);
            hBtnModeTun   = MakeBtn(hwnd, L"Весь трафик (TUN)", ID_BTN_MODE_TUN,   182, 76, 150, 32);

            NetConfig cfg; GetNetConfig(&cfg);
            hEditIp    = MakeEdit(hwnd, cfg.ip, ID_EDIT_IP, 24, 160, 232, 32, tm.tmHeight);
            hBtnScan   = MakeBtn(hwnd, L"", ID_BTN_SCAN,   264, 160, 32, 32, L"Найти прокси в сети");
            hBtnTest   = MakeBtn(hwnd, L"", ID_BTN_TEST,   304, 160, 32, 32, L"Проверить связь, пинг и страну");
            hBtnToggle = MakeBtn(hwnd, L"Подключить", ID_BTN_TOGGLE, 80, 252, 200, 40);

            char sp[16], lps[16]; snprintf(sp, 16, "%d", cfg.socksPort); snprintf(lps, 16, "%d", cfg.localPort);
            hEditSPort     = MakeEdit(hwnd, sp,       ID_EDIT_SPORT,  24,  88, 152, 30, tm.tmHeight);
            hEditLPort     = MakeEdit(hwnd, lps,      ID_EDIT_LPORT, 184,  88, 152, 30, tm.tmHeight);
            hEditUser      = MakeEdit(hwnd, cfg.user, ID_EDIT_USER,   24, 150, 312, 30, tm.tmHeight);
            hEditPass      = MakeEdit(hwnd, cfg.pass, ID_EDIT_PASS,   24, 212, 312, 30, tm.tmHeight, 38, true);
            g_passChar     = (wchar_t)SendMessageW(hEditPass, EM_GETPASSWORDCHAR, 0, 0); if (!g_passChar) g_passChar = L'*';
            hBtnShowPass   = MakeBtn(hwnd, L"", ID_BTN_SHOWPASS,    306, 214, 26, 26, L"Показать / скрыть пароль");
            hBtnTrayOpt    = MakeBtn(hwnd, L"", ID_BTN_TRAY_OPT,    296, 278, 40, 20, L"Сворачивать в трей при минимизации");
            hBtnAutoStart  = MakeBtn(hwnd, L"", ID_BTN_AUTOSTART,   296, 314, 40, 20, L"Запускать вместе с Windows в трей");
            hBtnAutoZapret = MakeBtn(hwnd, L"", ID_BTN_AUTO_ZAPRET, 296, 350, 40, 20, L"Возвращать Zapret после выключения TUN");
            hBtnDlTun      = MakeBtn(hwnd, L"", ID_BTN_DL_TUN,      304, 384, 32, 32, L"Скачать / проверить драйвер TUN (SHA-256)");
            hBtnStopZapret = MakeBtn(hwnd, L"", ID_BTN_STOP_ZAPRET, 304, 422, 32, 32, L"Остановить Zapret / WinDivert");

            g_zapretActive = IsZapretActive(); g_autoStart = IsAutoStartEnabled();
            g_screen = 1; SwitchScreen(0);

            g_nid.cbSize = sizeof(g_nid); g_nid.hWnd = hwnd; g_nid.uID = 1;
            g_nid.uFlags = NIF_MESSAGE|NIF_ICON|NIF_TIP; g_nid.uCallbackMessage = WM_APP_TRAY; g_nid.hIcon = g_trayIconOff;
            SafeCopyW(g_nid.szTip, 128, L"TunBridge — Отключено");
            if (Shell_NotifyIconW(NIM_ADD, &g_nid)) g_trayAdded = true;
            SetTimer(hwnd, TIMER_STATS, 1000, nullptr); RefreshControls();
            break;
        }
        case WM_ERASEBKGND: return 1;
        case WM_PAINT: { PAINTSTRUCT ps; HDC hd = BeginPaint(hwnd, &ps); PaintWindow(hwnd, hd); EndPaint(hwnd, &ps); break; }
        case WM_DRAWITEM: DrawOwnerButton((DRAWITEMSTRUCT*)lp); return TRUE;
        case WM_CTLCOLOREDIT:   SetTextColor((HDC)wp, COL_TEXT);    SetBkColor((HDC)wp, COL_SURFACE);    return (INT_PTR)g_brInput;
        case WM_CTLCOLORSTATIC: SetTextColor((HDC)wp, COL_TEXT_RO); SetBkColor((HDC)wp, COL_SURFACE_RO); return (INT_PTR)g_brInputRo;
        case WM_TIMER: {
            if (wp == TIMER_STATS) {
                if (g_running) {
                    if (g_mode == 1) {
                        if (g_tunProc && WaitForSingleObject(g_tunProc, 0) != WAIT_TIMEOUT) {
                            StopAll(); SetErrorMsg(L"Ошибка · Движок TUN остановился"); RefreshControls(); break;
                        }
                        if (g_tunIfIndex) {
                            MIB_IFROW r = {}; r.dwIndex = g_tunIfIndex;
                            if (GetIfEntry(&r) == NO_ERROR) {
                                DWORD cur = r.dwInOctets + r.dwOutOctets;
                                if (g_hasPrevOctets) InterlockedExchangeAdd64(&g_bytesTotal, (LONGLONG)(DWORD)(cur - g_prevTunOctets));
                                g_prevTunOctets = cur; g_hasPrevOctets = true;
                            }
                        }
                    }
                    if (IsWindowVisible(hwnd) && g_screen == 0) { RECT rt = { S(28), S(304), S(332), S(336) }; InvalidateRect(hwnd, &rt, FALSE); }
                }
                if (IsWindowVisible(hwnd) && g_screen == 1) {
                    bool zn = IsZapretActive(); if (zn != g_zapretActive) { g_zapretActive = zn; RefreshControls(); }
                }
            }
            break;
        }
        case WM_SYSCOMMAND:
            if ((wp & 0xFFF0) == SC_MINIMIZE && g_minimizeToTray && g_trayAdded) { ShowWindow(hwnd, SW_HIDE); return 0; }
            return DefWindowProcW(hwnd, msg, wp, lp);
        case WM_APP_AUTOSTART:
            if (!g_running && !g_busy && g_mode == 1) { StartSelectedMode(hwnd); RefreshControls(); }
            break;
        case WM_APP_AUTODL:
            StartDownloadTun(hwnd);
            break;
        case WM_APP_TUN_DONE: {
            if (wp == 1) {
                InterlockedExchange(&g_running, 1); SetErrorMsg(nullptr); UpdateTray(); LaunchProbeAsync(false);
            } else {
                RestoreZapretIfNeeded(); g_zapretActive = IsZapretActive();
                char eb[512] = {}; EnterCriticalSection(&g_logCs); SafeCopyA(eb, 512, g_tunLastErr); LeaveCriticalSection(&g_logCs);
                int c = (int)lp;
                if (c == 11)      SetErrorMsg(L"Ошибка · Прокси недоступен");
                else if (c == 12) SetErrorMsg(L"Ошибка · Не SOCKS5/HTTP прокси");
                else if (c == 13) SetErrorMsg(L"Ошибка · Неверный логин/пароль");
                else if (eb[0]) { wchar_t wm[192]; _snwprintf(wm, 191, L"Ошибка · %hs", eb); wm[191] = 0; SetErrorMsg(wm); }
                else if (c == 1)  SetErrorMsg(L"Ошибка · Драйвер TUN не найден");
                else if (c == 2)  SetErrorMsg(L"Ошибка · Сбой запуска tun2socks");
                else if (c == 3)  SetErrorMsg(L"Ошибка · Адаптер TunBridge не создан");
                else              SetErrorMsg(L"Ошибка · Сбой маршрутов Windows");
            }
            RefreshControls(); break;
        }
        case WM_APP_DL_DONE:
            SetErrorMsg(wp == 1 ? nullptr : L"Ошибка · Сбой загрузки / SHA-256"); RefreshControls(); break;
        case WM_APP_SCAN_DONE: {
            if (wp == 1) {
                struct in_addr a; a.s_addr = (ULONG)lp; char is[64] = {}; inet_ntop(AF_INET, &a, is, sizeof(is));
                SetWindowTextA(hEditIp, is); SaveConfig();
                g_testIconState = 0; g_ipLabelState = 1; SafeCopyW(g_ipLabelText, 48, L"Найден"); SetErrorMsg(nullptr);
            } else { g_ipLabelState = -1; SafeCopyW(g_ipLabelText, 48, L"Не найден"); }
            RefreshControls(); break;
        }
        case WM_APP_PROBE_DONE: {
            auto pr = (ProbeResult*)lp; if (!pr) break;
            if (pr->gen == g_connGen || pr->fromTestBtn) {
                if (pr->err == 0) {
                    if (g_running || pr->fromTestBtn) {
                        g_pingMs = pr->pingMs; SafeCopyA(g_countryCode, sizeof(g_countryCode), pr->cc); UpdateTray();
                    }
                    if (pr->fromTestBtn) {
                        g_testIconState = 1; g_ipLabelState = 1;
                        if (g_countryCode[0]) _snwprintf(g_ipLabelText, 47, L"ОК · %hs · %d мс", g_countryCode, pr->pingMs);
                        else                  _snwprintf(g_ipLabelText, 47, L"ОК · %d мс", pr->pingMs);
                        g_ipLabelText[47] = 0;
                    }
                } else {
                    if (g_running && pr->gen == g_connGen) g_pingMs = -2;
                    if (pr->fromTestBtn) {
                        g_testIconState = -1; g_ipLabelState = -1;
                        SafeCopyW(g_ipLabelText, 48, pr->err==1 ? L"Нет связи" : (pr->err==2 ? L"Не прокси" : (pr->err==3 ? L"Неверный пароль" : L"Нет VPN-сети")));
                    }
                }
            }
            free(pr); RefreshControls(); break;
        }
        case WM_APP_TRAY: {
            if (lp == WM_LBUTTONUP || lp == WM_LBUTTONDBLCLK) { ShowWindow(hwnd, SW_SHOW); ShowWindow(hwnd, SW_RESTORE); SetForegroundWindow(hwnd); }
            else if (lp == WM_RBUTTONUP) {
                POINT pt; GetCursorPos(&pt); HMENU hm = CreatePopupMenu();
                AppendMenuW(hm, MF_STRING, ID_TRAY_SHOW, L"Открыть");
                AppendMenuW(hm, MF_STRING, ID_TRAY_TOGGLE, g_running ? L"Отключить" : L"Подключить");
                AppendMenuW(hm, MF_SEPARATOR, 0, nullptr); AppendMenuW(hm, MF_STRING, ID_TRAY_EXIT, L"Выход");
                SetForegroundWindow(hwnd); TrackPopupMenu(hm, TPM_RIGHTBUTTON, pt.x, pt.y, 0, hwnd, nullptr); DestroyMenu(hm);
            }
            break;
        }
        case WM_COMMAND: {
            int id = LOWORD(wp), cd = HIWORD(wp);
            if (cd == EN_SETFOCUS) { g_focusedEditId = id; InvalidateRect(hwnd, nullptr, FALSE); break; }
            if (cd == EN_KILLFOCUS){ if (g_focusedEditId == id) g_focusedEditId = 0; InvalidateRect(hwnd, nullptr, FALSE); break; }
            if (cd == EN_CHANGE && id == ID_EDIT_IP) {
                if (g_testIconState || g_ipLabelState) { g_testIconState = g_ipLabelState = 0; g_ipLabelText[0] = 0; InvalidateRect(hwnd, nullptr, FALSE); }
                break;
            }
            if (id == ID_BTN_SETTINGS) SwitchScreen(1);
            else if (id == ID_BTN_BACK) { g_testIconState = g_ipLabelState = 0; g_ipLabelText[0] = 0; SwitchScreen(0); }
            else if (id == ID_BTN_TRAY_WIN && g_trayAdded) ShowWindow(hwnd, SW_HIDE);
            else if (id == ID_TRAY_SHOW) { ShowWindow(hwnd, SW_SHOW); ShowWindow(hwnd, SW_RESTORE); SetForegroundWindow(hwnd); }
            else if (id == ID_BTN_TRAY_OPT) { g_minimizeToTray = !g_minimizeToTray; SaveConfig(); InvalidateRect(hBtnTrayOpt, nullptr, FALSE); }
            else if (id == ID_BTN_AUTOSTART) { SetAutoStartEnabled(!g_autoStart); g_autoStart = IsAutoStartEnabled(); InvalidateRect(hBtnAutoStart, nullptr, FALSE); }
            else if (id == ID_BTN_AUTO_ZAPRET) { g_autoRestoreZapret = !g_autoRestoreZapret; SaveConfig(); InvalidateRect(hBtnAutoZapret, nullptr, FALSE); }
            else if (id == ID_BTN_DL_TUN) StartDownloadTun(hwnd);
            else if (id == ID_BTN_STOP_ZAPRET && !g_busy) {
                ClearSavedZapretState();
                if (IsElevated()) StopZapret();
                else {
                    SHELLEXECUTEINFOW sei = { sizeof(sei), SEE_MASK_NOCLOSEPROCESS, hwnd, L"runas", g_exePath, L"--stop-zapret", g_exeDir, SW_HIDE };
                    if (ShellExecuteExW(&sei) && sei.hProcess) { WaitForSingleObject(sei.hProcess, 6000); CloseHandle(sei.hProcess); }
                }
                g_zapretActive = IsZapretActive(); RefreshControls();
            } else if ((id == ID_BTN_MODE_PROXY || id == ID_BTN_MODE_TUN) && !g_running && !g_busy) {
                g_mode = (id == ID_BTN_MODE_TUN) ? 1 : 0; SetErrorMsg(nullptr); SaveConfig(); RefreshControls();
            } else if ((id == ID_BTN_TOGGLE || id == ID_TRAY_TOGGLE) && !g_busy) {
                if (g_running) { StopAll(); SetErrorMsg(nullptr); } else StartSelectedMode(hwnd);
                RefreshControls();
            } else if (id == ID_BTN_SCAN && !g_running && !g_busy && InterlockedCompareExchange(&g_scanning, 1, 0) == 0) {
                SaveConfig(); g_ipLabelState = 2; SafeCopyW(g_ipLabelText, 48, L"Поиск..."); RefreshControls();
                NetConfig cfg; GetNetConfig(&cfg);
                HANDLE ht = CreateThread(nullptr, 0, ScanThread, (LPVOID)(INT_PTR)cfg.socksPort, 0, nullptr);
                if (ht) CloseHandle(ht); else InterlockedExchange(&g_scanning, 0);
            } else if (id == ID_BTN_TEST && !g_busy && InterlockedCompareExchange(&g_testing, 1, 0) == 0) {
                SaveConfig(); g_testIconState = 0; g_ipLabelState = 2; SafeCopyW(g_ipLabelText, 48, L"Проверка..."); RefreshControls();
                LaunchProbeAsync(true);
            } else if (id == ID_BTN_SHOWPASS) {
                g_passVisible = !g_passVisible; SendMessageW(hEditPass, EM_SETPASSWORDCHAR, g_passVisible ? 0 : g_passChar, 0);
                InvalidateRect(hEditPass, nullptr, TRUE); InvalidateRect(hBtnShowPass, nullptr, FALSE);
            } else if (id == ID_TRAY_EXIT) SendMessageW(hwnd, WM_CLOSE, 0, 0);
            break;
        }
        case WM_CLOSE:
            InterlockedExchange(&g_shuttingDown, 1); SaveConfig(); StopAll(); DestroyWindow(hwnd); break;
        case WM_DESTROY: {
            KillTimer(hwnd, TIMER_STATS); StopAll();
            if (g_trayAdded) { Shell_NotifyIconW(NIM_DELETE, &g_nid); g_trayAdded = false; }
            HICON ics[] = { g_appIconBig, g_appIconSmall, g_trayIconOn, g_trayIconOff };
            for (HICON i : ics) if (i) DestroyIcon(i);
            HFONT fts[] = { g_fontTitle, g_fontSemi, g_fontBody, g_fontSeg, g_fontSegSemi, g_fontSmall, g_fontMono, g_fontIcon };
            for (HFONT f : fts) if (f) DeleteObject(f);
            if (g_brInput) DeleteObject(g_brInput);
            if (g_brInputRo) DeleteObject(g_brInputRo);
            g_hwnd = nullptr; PostQuitMessage(0); break;
        }
        default: return DefWindowProcW(hwnd, msg, wp, lp);
    }
    return 0;
}

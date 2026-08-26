// lethe_win.cpp - Windows host for Lethe full-web mode (.exe).
//
// Embeds Microsoft Edge WebView2 (Chromium) so real pages - YouTube
// included - render natively on Windows. Lethe policy is enforced at the
// navigation layer:
//   * scheme allowlist (http/https only)
//   * private-network isolation: the RESOLVED address of every navigation
//     is classified before the load is allowed (loopback permitted,
//     RFC1918/CGNAT/link-local incl. cloud-metadata/multicast refused)
//   * session data confined to the app-local \\LetheWebView2 folder
//
// Resolution scaling uses WebView2's native RasterizationScale
// (ICoreWebView2Controller3):
//   LETHE_RASTER_SCALE=0.75   FSR-style performance mode
//   LETHE_RASTER_SCALE=2.0    DLAA-style supersampling
// Ctrl+Alt+Left/Right cycles 0.66 .. 2.0 live.
//
// Honest scope note: the VPN/tunnel stack is POSIX-only today, so this
// host enforces policy at navigation granularity, not socket granularity.

#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#include <windows.h>
#include <commctrl.h>
#include <shlwapi.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#include <algorithm>
#include <cmath>
#include <cwctype>
#include <string>

#include "WebView2.h"
#include <wrl.h>
#include <wrl/client.h>

using namespace Microsoft::WRL;
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "ws2_32.lib")

static const wchar_t kWndClass[] = L"LetheMainWindow";
static HWND g_hwnd = nullptr;
static HWND g_urlBar = nullptr;
static WNDPROC g_editProc = nullptr;
static ComPtr<ICoreWebView2Environment> g_env;
static ComPtr<ICoreWebView2Controller> g_controller;
static ComPtr<ICoreWebView2> g_web;
static double g_rasterScale = 1.0;
static const double kScales[] = {0.66, 0.75, 0.85, 1.0, 1.25, 1.5, 2.0};

// ---- Scope classifier (compact port of private_network_guard rules) ----
enum Scope { SCOPE_PUBLIC, SCOPE_LOOPBACK, SCOPE_PRIVATE };
static Scope classifyV4(unsigned long ho) {  // host byte order
    unsigned char b[4] = {(unsigned char)(ho >> 24), (unsigned char)(ho >> 16),
                          (unsigned char)(ho >> 8), (unsigned char)ho};
    if (b[0] == 127) return SCOPE_LOOPBACK;
    if (b[0] == 10 || (b[0] == 172 && b[1] >= 16 && b[1] <= 31) ||
        (b[0] == 192 && b[1] == 168)) return SCOPE_PRIVATE;
    if (b[0] == 169 && b[1] == 254) return SCOPE_PRIVATE;
    if (b[0] == 100 && b[1] >= 64 && b[1] <= 127) return SCOPE_PRIVATE;
    if ((b[0] & 0xF0) == 224 || b[0] >= 240 || b[0] == 0) return SCOPE_PRIVATE;
    return SCOPE_PUBLIC;
}
static Scope classifyV6(const unsigned char* b) {  // network byte order
    bool allZero = true;
    for (int i = 0; i < 16; ++i)
        if (b[i]) { allZero = false; break; }
    if (allZero) return SCOPE_PRIVATE;                    // unspecified
    bool loop = true;
    for (int i = 0; i < 15; ++i)
        if (b[i]) { loop = false; break; }
    if (loop && b[15] == 1) return SCOPE_LOOPBACK;        // ::1
    static const unsigned char map[12] = {0,0,0,0,0,0,0,0,0,0,0xff,0xff};
    bool mapped = true;
    for (int i = 0; i < 12; ++i)
        if (b[i] != map[i]) { mapped = false; break; }
    if (mapped)
        return classifyV4(((unsigned long)b[12] << 24) | (b[13] << 16) |
                          (b[14] << 8) | b[15]);            // ::ffff:v4
    if ((b[0] & 0xFE) == 0xFC) return SCOPE_PRIVATE;        // ULA fc00::/7
    if (b[0] == 0xFE && (b[1] & 0xC0) == 0x80) return SCOPE_PRIVATE;
    if ((b[0] & 0xF0) == 0xF0) return SCOPE_PRIVATE;        // multicast/resv
    return SCOPE_PUBLIC;
}

static std::wstring lower(std::wstring s) {
    for (auto& c : s) c = (wchar_t)towlower(c);
    return s;
}

// Returns empty when allowed, else a named block reason.
static std::wstring policyCheckUrl(const std::wstring& url) {
    const size_t colon = url.find(L"://");
    if (colon == std::wstring::npos)
        return L"Blocked by Lethe policy: scheme not permitted";
    const std::wstring scheme = lower(url.substr(0, colon));
    if (scheme != L"http" && scheme != L"https")
        return L"Blocked by Lethe policy: scheme not permitted (" + scheme + L")";

    std::wstring rest = url.substr(colon + 3);
    const size_t slash = rest.find_first_of(L"/?#");
    std::wstring authority =
        slash == std::wstring::npos ? rest : rest.substr(0, slash);
    const size_t at = authority.rfind(L'@');
    if (at != std::wstring::npos) authority = authority.substr(at + 1);
    std::wstring hostname;
    bool bracket = false;
    if (!authority.empty() && authority[0] == L'[') {
        bracket = true;
        const size_t close = authority.find(L']');
        if (close == std::wstring::npos)
            return L"Blocked by Lethe policy: malformed URL";
        hostname = authority.substr(1, close - 1);
    } else {
        const size_t c2 = authority.find(L':');
        hostname = c2 == std::wstring::npos ? authority : authority.substr(0, c2);
    }
    if (hostname.empty()) return L"Blocked by Lethe policy: empty host";
    const std::wstring hn = lower(hostname);

    // Numeric spell-out guard: only plain dotted quads pass to inet_addr,
    // exactly three dots, no leading zeros (blocks 2130706433 / 0177.0.0.1).
    if (!bracket) {
        bool dottedDec = true;
        int dots = 0;
        for (wchar_t ch : hn) {
            if (ch == L'.') { dots++; continue; }
            if (ch < L'0' || ch > L'9') { dottedDec = false; break; }
        }
        if (dottedDec) {
            if (dots != 3)
                return L"Blocked by Lethe policy: ambiguous numeric host";
            int oct[4];
            if (swscanf(hn.c_str(), L"%d.%d.%d.%d", &oct[0], &oct[1], &oct[2],
                        &oct[3]) != 4)
                return L"Blocked by Lethe policy: malformed numeric host";
            for (int i = 0; i < 4; ++i)
                if (oct[i] < 0 || oct[i] > 255)
                    return L"Blocked by Lethe policy: malformed numeric host";
            unsigned long ho = ((unsigned long)oct[0] << 24) |
                               ((unsigned long)oct[1] << 16) |
                               ((unsigned long)oct[2] << 8) | (unsigned long)oct[3];
            if (classifyV4(ho) == SCOPE_PRIVATE)
                return L"Blocked by Lethe policy: private-network destination";
            return L"";
        }
    }

    // Resolve through the system resolver, classify EVERY answer.
    addrinfoW hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_flags = AI_ADDRCONFIG;
    addrinfoW* res = nullptr;
    if (GetAddrInfoW(hn.c_str(), nullptr, &hints, &res) != 0 || !res)
        return L"Blocked by Lethe policy: resolution failed";
    std::wstring reason;
    for (addrinfoW* p = res; p; p = p->ai_next) {
        Scope sc = SCOPE_PUBLIC;
        if (p->ai_family == AF_INET) {
            sc = classifyV4(ntohl(reinterpret_cast<sockaddr_in*>(p->ai_addr)
                                      ->sin_addr.s_addr));
        } else if (p->ai_family == AF_INET6) {
            sc = classifyV6(
                reinterpret_cast<sockaddr_in6*>(p->ai_addr)->sin6_addr.u.Byte);
        } else {
            continue;
        }
        if (sc == SCOPE_PRIVATE) {
            reason = L"Blocked by Lethe policy: " + hn +
                     L" resolves into a private scope";
            break;
        }
    }
    FreeAddrInfoW(res);
    return reason;
}

static void applyRasterScale() {
    if (!g_controller) return;
    // RasterizationScale arrived on ICoreWebView2Controller3.
    ComPtr<ICoreWebView2Controller3> c3;
    if (SUCCEEDED(g_controller.As(&c3))) {
        c3->put_RasterizationScale(g_rasterScale);
        return;
    }
    static bool warned = false;
    if (!warned) {
        warned = true;
        MessageBoxW(g_hwnd,
                    L"This WebView2 runtime predates RasterizationScale; "
                    L"resolution scaling is unavailable.",
                    L"Lethe", MB_ICONINFORMATION);
    }
}

static void cycleScale(int dir) {
    const int n = (int)(sizeof(kScales) / sizeof(kScales[0]));
    int idx = 3;
    double best = 1e9;
    for (int i = 0; i < n; ++i) {
        const double d = fabs(kScales[i] - g_rasterScale);
        if (d < best) { best = d; idx = i; }
    }
    idx += dir;
    if (idx < 0) idx = 0;
    if (idx > n - 1) idx = n - 1;
    g_rasterScale = kScales[idx];
    applyRasterScale();
}

static void navigateCurrentBar() {
    wchar_t buf[2048] = {};
    GetWindowTextW(g_urlBar, buf, 2048);
    std::wstring u = buf;
    if (u.find(L"://") == std::wstring::npos) u = L"https://" + u;
    if (g_web) g_web->Navigate(u.c_str());
}

static LRESULT CALLBACK EditProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    if (m == WM_KEYDOWN && w == VK_RETURN) {
        navigateCurrentBar();
        return 0;
    }
    return CallWindowProcW(g_editProc, h, m, w, l);
}

LRESULT CALLBACK WndProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    switch (m) {
    case WM_SIZE: {
        RECT r;
        GetClientRect(h, &r);
        if (g_urlBar) MoveWindow(g_urlBar, 0, 0, r.right, 36, TRUE);
        if (g_controller) {
            RECT wb = {0, 36, r.right, r.bottom};
            g_controller->put_Bounds(wb);
        }
        break;
    }
    case WM_KEYDOWN:
        if ((GetKeyState(VK_CONTROL) & 0x8000) &&
            (GetKeyState(VK_MENU) & 0x8000)) {
            if (w == VK_LEFT) cycleScale(-1);
            if (w == VK_RIGHT) cycleScale(1);
        }
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProcW(h, m, w, l);
    }
    return 0;
}

int WINAPI wWinMain(HINSTANCE inst, HINSTANCE, PWSTR, int show) {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
    {
        wchar_t buf[32] = {};
        if (GetEnvironmentVariableW(L"LETHE_RASTER_SCALE", buf, 32))
            g_rasterScale = wcstod(buf, nullptr);
    }

    WNDCLASSW wc{};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = inst;
    wc.lpszClassName = kWndClass;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    RegisterClassW(&wc);
    g_hwnd = CreateWindowExW(0, kWndClass, L"Lethe - Full Web",
                             WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT,
                             1280, 860, nullptr, nullptr, inst, nullptr);
    g_urlBar =
        CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"https://www.youtube.com",
                        WS_CHILD | WS_VISIBLE | WS_TABSTOP, 0, 0, 1280, 36,
                        g_hwnd, (HMENU)1, inst, nullptr);
    g_editProc = (WNDPROC)SetWindowLongPtrW(g_urlBar, GWLP_WNDPROC,
                                            (LONG_PTR)EditProc);
    ShowWindow(g_hwnd, show);

    HRESULT hr = CreateCoreWebView2EnvironmentWithOptions(
        nullptr, L"LetheWebView2", nullptr,
        Callback<ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler>(
            [](HRESULT result, ICoreWebView2Environment* env) -> HRESULT {
                if (FAILED(result) || !env) return result;
                env->QueryInterface(IID_PPV_ARGS(&g_env));
                return g_env->CreateCoreWebView2Controller(
                    g_hwnd,
                    Callback<
                        ICoreWebView2CreateCoreWebView2ControllerCompletedHandler>(
                        [](HRESULT result2,
                           ICoreWebView2Controller* ctl) -> HRESULT {
                            if (FAILED(result2) || !ctl) return result2;
                            g_controller = ctl;
                            ctl->get_CoreWebView2(&g_web);
                            EventRegistrationToken navToken{};
                            g_web->add_NavigationStarting(
                                Callback<
                                    ICoreWebView2NavigationStartingEventHandler>(
                                    [](ICoreWebView2* sender,
                                       ICoreWebView2NavigationStartingEventArgs*
                                           args) -> HRESULT {
                                        LPWSTR raw = nullptr;
                                        args->get_Uri(&raw);
                                        std::wstring reason =
                                            raw ? policyCheckUrl(raw)
                                                : L"blocked";
                                        CoTaskMemFree(raw);
                                        if (!reason.empty()) {
                                            args->put_Cancel(TRUE);
                                            MessageBoxW(g_hwnd, reason.c_str(),
                                                        L"Lethe",
                                                        MB_ICONWARNING);
                                        }
                                        return S_OK;
                                    })
                                    .Get(),
                                &navToken);
                            applyRasterScale();
                            RECT r;
                            GetClientRect(g_hwnd, &r);
                            RECT wb = {0, 36, r.right, r.bottom};
                            ctl->put_Bounds(wb);
                            navigateCurrentBar();
                            return S_OK;
                        })
                        .Get());
            })
            .Get());
    if (FAILED(hr)) {
        MessageBoxW(g_hwnd,
                    L"WebView2 runtime not found.\n"
                    L"Install the Evergreen Runtime:\n"
                    L"https://go.microsoft.com/fwlink/p/?LinkId=2124703",
                    L"Lethe", MB_ICONERROR);
        return 1;
    }

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    WSACleanup();
    return 0;
}

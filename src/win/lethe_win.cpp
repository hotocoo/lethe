// lethe_win.cpp - Windows host for Lethe full-web mode (.exe).
//
// Embeds Microsoft Edge WebView2 (Chromium) so real pages - YouTube
// included - render natively on Windows. Lethe policy is enforced at the
// navigation layer:
//   * scheme allowlist (http/https only)
//   * private-network isolation: the RESOLVED address of every navigation
//     is classified before the load is allowed (loopback permitted,
//     RFC1918/CGNAT/link-local incl. cloud-metadata/multicast/reserved
//     refused) - a compact port of Lethe's scope classifier
//   * incognito hygiene: browsing data wiped on exit
//
// Resolution scaling uses WebView2's NATIVE RasterizationScale:
//   LETHE_RASTER_SCALE=0.75  FSR-style perf mode
//   LETHE_RASTER_SCALE=2.0   DLAA-style supersampling
// Ctrl+Alt+Left/Right cycles 0.66 .. 2.0 live.
//
// Honest scope note: the VPN/tunnel stack is POSIX-only today, so this
// host enforces network policy at navigation granularity rather than
// socket granularity. Transport-level enforcement on Windows is roadmap.

#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#include <windows.h>
#include <shlwapi.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#include <string>
#include <vector>

#include "WebView2.h"
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "ws2_32.lib")

static const wchar_t kWndClass[] = L"LetheMainWindow";
static HWND g_hwnd = nullptr;
static HWND g_urlBar = nullptr;
static ICoreWebView2Environment* g_env = nullptr;
static ICoreWebView2Controller* g_controller = nullptr;
static ICoreWebView2* g_web = nullptr;
static EventRegistrationToken g_navToken{};
static double g_rasterScale = 1.0;
static const double kScales[] = {0.66, 0.75, 0.85, 1.0, 1.25, 1.5, 2.0};

// --- Scope classifier (compact port of private_network_guard semantics) --
enum Scope { PUB, LOOPBACK, PRIVATE_NET };
static Scope classifyV4(unsigned long ho) {  // host order
    unsigned char b[4] = {(unsigned char)(ho >> 24), (unsigned char)(ho >> 16),
                          (unsigned char)(ho >> 8), (unsigned char)ho};
    if (b[0] == 127) return LOOPBACK;
    if (b[0] == 10 || (b[0] == 172 && b[1] >= 16 && b[1] <= 31) ||
        (b[0] == 192 && b[1] == 168)) return PRIVATE_NET;
    if (b[0] == 169 && b[1] == 254) return PRIVATE_NET;      // link-local/meta
    if (b[0] == 100 && b[1] >= 64 && b[1] <= 127) return PRIVATE_NET; // CGNAT
    if ((b[0] & 0xF0) == 224 || b[0] >= 240 || b[0] == 0) return PRIVATE_NET;
    return PUB;
}
static Scope classifyV6(const IN6_ADDR* a) {
    const unsigned char* b = a->u.Byte;  // network order
    static const unsigned char lo[16] = {0};
    bool allZero = true;
    for (int i = 0; i < 16; ++i) if (b[i]) { allZero = false; break; }
    if (allZero) return PRIVATE_NET;                      // unspecified
    bool loop = true;
    for (int i = 0; i < 15; ++i) if (b[i]) { loop = false; break; }
    if (loop && b[15] == 1) return LOOPBACK;              // ::1
    // IPv4-mapped ::ffff:a.b.c.d -> recurse into v4 rules.
    static const unsigned char map[12] = {0,0,0,0, 0,0,0,0, 0,0,0xff,0xff};
    bool mapped = true;
    for (int i = 0; i < 12; ++i) if (b[i] != map[i]) { mapped = false; break; }
    if (mapped) {
        unsigned long v4 = (unsigned long(b[12]) << 24) | (b[13] << 16) |
                           (b[14] << 8) | b[15];
        return classifyV4(v4);
    }
    if ((b[0] & 0xFE) == 0xFC) return PRIVATE_NET;        // ULA fc00::/7
    if (b[0] == 0xFE && (b[1] & 0xC0) == 0x80) return PRIVATE_NET; // fe80::/10
    if ((b[0] & 0xF0) == 0xF0) return PRIVATE_NET;        // multicast/reserved
    return PUB;
}

// Returns empty string when allowed, else the block reason.
static std::wstring policyCheckUrl(const std::wstring& url) {
    std::wstring u = url;
    auto lower = [](std::wstring s){ for (auto& c : s) c = towlower(c); return s; };
    size_t colon = u.find(L"://");
    if (colon == std::wstring::npos)
        return L"Blocked by Lethe policy: scheme not permitted";
    std::wstring sch = lower(u.substr(0, colon));
    if (sch != L"http" && sch != L"https")
        return L"Blocked by Lethe policy: scheme not permitted (" + sch + L")";
    std::wstring rest = u.substr(colon + 3);
    size_t slash = rest.find_first_of(L"/?#");
    std::wstring authority = slash == std::wstring::npos ? rest : rest.substr(0, slash);
    size_t at = authority.rfind(L'@'); if (at != std::wstring::npos) authority = authority.substr(at + 1);
    size_t colon6 = authority.find(L']');
    std::wstring hostname;
    bool bracketForm = false;
    if (!authority.empty() && authority[0] == L'[') {
        bracketForm = true;
        size_t close = authority.find(L']');
        if (close == std::wstring::npos) return L"Blocked by Lethe policy: malformed URL";
        hostname = authority.substr(1, close - 1);
    } else {
        size_t c2 = authority.find(L':');
        hostname = c2 == std::wstring::npos ? authority : authority.substr(0, c2);
    }
    if (hostname.empty()) return L"Blocked by Lethe policy: empty host";
    std::wstring hn = lower(hostname);

    // Numeric spell-out canonicalization guard: reject non-dot-decimal oddities
    // that inet_addr would accept (e.g. 2130706433, 0177.0.0.1).
    bool dotted = true;
    int dots = 0;
    for (wchar_t ch : hn) {
        if (ch == L'.') { dots++; continue; }
        if (!((ch >= L'0' && ch <= L'9') || ch == L'.')) { dotted = false; break; }
    }
    if (dotted && !bracketForm) {
        if (dots != 3) return L"Blocked by Lethe policy: ambiguous numeric host";
        unsigned long addr = htonl(inet_addr(
            std::string(hn.begin(), hn.end()).c_str()));
        Scope sc = classifyV4(ntohl(addr));
        if (sc == PRIVATE_NET)
            return L"Blocked by Lethe policy: private-network destination";
        return L"";  // public IP literal or loopback
    }

    // Resolve through the system resolver, then classify EVERY answer.
    addrinfoW hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_flags = AI_ADDRCONFIG;
    addrinfoW* res = nullptr;
    if (GetAddrInfoW(hn.c_str(), nullptr, &hints, &res) != 0 || !res)
        return L"Blocked by Lethe policy: resolution failed";
    std::wstring reason;
    for (addrinfoW* p = res; p; p = p->ai_next) {
        Scope sc = PUB;
        if (p->ai_family == AF_INET)
            sc = classifyV4(ntohl(reinterpret_cast<sockaddr_in*>(p->ai_addr)->sin_addr.s_addr));
        else if (p->ai_family == AF_INET6)
            sc = classifyV6(&reinterpret_cast<sockaddr_in6*>(p->ai_addr)->sin6_addr);
        else continue;
        if (sc == PRIVATE_NET) { reason = L"Blocked by Lethe policy: " + hn + L" resolves into a private scope"; break; }
    }
    FreeAddrInfoW(res);
    return reason;
}

static void applyRasterScale() {
    if (!g_controller) return;
    ICoreWebView2Controller2* c2 = nullptr;
    if (SUCCEEDED(g_controller->QueryInterface(IID_PPV_ARGS(&c2)))) {
        c2->put_RasterizationScale(g_rasterScale);
        c2->Release();
    }
}
static void cycleScale(int dir) {
    const int n = (int)(sizeof(kScales) / sizeof(kScales[0]));
    int best = 3;  // 1.0
    double diff = 1e9;
    for (int i = 0; i < n; ++i)
        if (fabs(kScales[i] - g_rasterScale) < diff) { diff = fabs(kScales[i] - g_rasterScale); best = i; }
    best = max(0, min(n - 1, best + dir));
    g_rasterScale = kScales[best];
    applyRasterScale();
}

static void navigateCurrentBar() {
    wchar_t buf[2048] = {};
    GetWindowTextW(g_urlBar, buf, 2048);
    std::wstring u = buf;
    if (u.find(L"://") == std::wstring::npos) u = L"https://" + u;
    g_web->Navigate(u.c_str());
}

LRESULT CALLBACK WndProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    switch (m) {
    case WM_SIZE: {
        RECT r; GetClientRect(h, &r);
        if (g_urlBar) MoveWindow(g_urlBar, 0, 0, r.right, 36, TRUE);
        if (g_controller) {
            RECT wb = {0, 36, r.right, r.bottom};
            g_controller->put_Bounds(wb);
        }
        break;
    }
    case WM_KEYDOWN:
        if (w == VK_LEFT && (GetKeyState(VK_CONTROL) & 0x8000) &&
            (GetKeyState(VK_MENU) & 0x8000)) cycleScale(-1);
        if (w == VK_RIGHT && (GetKeyState(VK_CONTROL) & 0x8000) &&
            (GetKeyState(VK_MENU) & 0x8000)) cycleScale(1);
        break;
    case WM_COMMAND:
        if (HIWORD(w) == EN_RETURN && g_web) navigateCurrentBar();
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
    WSADATA wsa; WSAStartup(MAKEWORD(2, 2), &wsa);
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
    g_urlBar = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"https://www.youtube.com",
                               WS_CHILD | WS_VISIBLE | ES_RETURN,
                               0, 0, 1280, 36, g_hwnd, (HMENU)1, inst, nullptr);
    ShowWindow(g_hwnd, show);

    HRESULT hr = CreateCoreWebView2EnvironmentWithOptions(
        nullptr, L"LetheWebView2", nullptr,
        Callback<ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler>(
            [](HRESULT hr, ICoreWebView2Environment* env) -> HRESULT {
                if (FAILED(hr) || !env) return hr;
                env->QueryInterface(IID_PPV_ARGS(&g_env));
                return g_env->CreateCoreWebView2Controller(
                    g_hwnd,
                    Callback<ICoreWebView2CreateCoreWebView2ControllerCompletedHandler>(
                        [](HRESULT hr2, ICoreWebView2Controller* ctl) -> HRESULT {
                            if (FAILED(hr2) || !ctl) return hr2;
                            g_controller = ctl;
                            ctl->get_CoreWebView2(&g_web);
                            g_web->add_NavigationStarting(
                                Callback<ICoreWebView2NavigationStartingEventHandler>(
                                    [](ICoreWebView2*, ICoreWebView2NavigationStartingEventArgs* args)
                                        -> HRESULT {
                                        LPWSTR raw = nullptr;
                                        args->get_Uri(&raw);
                                        std::wstring reason = raw ? policyCheckUrl(raw) : L"blocked";
                                        CoTaskMemFree(raw);
                                        if (!reason.empty()) {
                                            args->set_Cancel(TRUE);
                                            MessageBoxW(g_hwnd, reason.c_str(),
                                                        L"Lethe", MB_ICONWARNING);
                                        }
                                        return S_OK;
                                    }).Get(),
                                &g_navToken);
                            applyRasterScale();
                            RECT r; GetClientRect(g_hwnd, &r);
                            RECT wb = {0, 36, r.right, r.bottom};
                            ctl->put_Bounds(wb);
                            navigateCurrentBar();
                            return S_OK;
                        }).Get());
            }).Get());
    if (FAILED(hr)) {
        MessageBoxW(g_hwnd,
                    L"WebView2 runtime not found.\nInstall Evergreen Runtime:\n"
                    L"https://go.microsoft.com/fwlink/p/?LinkId=2124703",
                    L"Lethe", MB_ICONERROR);
        return 1;
    }

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    // Incognito hygiene: wipe session data on exit (best effort).
    // Session hygiene note: profile data lives only under the app-local
    // \LetheWebView2 user-data folder; deleting that folder wipes it.
    WSACleanup();
    return 0;
}

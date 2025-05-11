#include "utils.h"
#include <tlhelp32.h>

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif



// Gets the process handle of a process of name szProcessName
BOOL GetRemoteProcessHandle(LPWSTR szProcessName, DWORD* dwProcessId, HANDLE* hProcess) {

	HANDLE			hSnapShot		= NULL;
	PROCESSENTRY32W	Proc			= { .dwSize = sizeof(PROCESSENTRY32W) };

	// Takes a snapshot of the currently running processes

	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hSnapShot == INVALID_HANDLE_VALUE){
		DebugPrint("[!] CreateToolhelp32Snapshot Failed With Error : %d \n", GetLastError());
		goto _EndOfFunction;
	}

	// Retrieves information about the first process encountered in the snapshot.
	if (!Process32FirstW(hSnapShot, &Proc)) {
		DebugPrint("[!] Process32FirstW Failed With Error : %d \n", GetLastError());
		goto _EndOfFunction;
	}

	do {

		WCHAR LowerName[MAX_PATH * 2];

		if (Proc.szExeFile) {

			DWORD	dwSize = lstrlenW(Proc.szExeFile);
			DWORD   i = 0;

			RtlSecureZeroMemory(LowerName, MAX_PATH * 2);

			// Converting each charachter in Proc.szExeFile to a lowercase character and saving it
			// in LowerName to do the wcscmp call later

			if (dwSize < MAX_PATH * 2) {

				for (; i < dwSize; i++)
					LowerName[i] = (WCHAR)tolower(Proc.szExeFile[i]);

				LowerName[i++] = '\0';
			}
		}

		// Compare the enumerated process path with what is passed
		if (wcscmp(LowerName, szProcessName) == 0) {
			// Save the process ID 
			*dwProcessId	= Proc.th32ProcessID;
			// Open a process handle and return

			*hProcess		= OpenProcess(PROCESS_ALL_ACCESS, FALSE, Proc.th32ProcessID);

			if (*hProcess == NULL)
				DebugPrint("[!] OpenProcess Failed With Error : %d \n", GetLastError());

			break;
		}

	// Retrieves information about the next process recorded the snapshot.
	// while there is still a valid output ftom Process32NextW, continue looping
	} while (Process32NextW(hSnapShot, &Proc));
	


_EndOfFunction:
	if (hSnapShot != NULL)
		CloseHandle(hSnapShot);
	if (dwProcessId == NULL || *dwProcessId == 0 || hProcess == NULL || *hProcess == NULL)
		return FALSE;
	return TRUE;
}


#define InitializeObjectAttributes(p, n, a, r, s) { \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES); \
    (p)->RootDirectory = r; \
    (p)->Attributes = a; \
    (p)->ObjectName = n; \
    (p)->SecurityDescriptor = s; \
    (p)->SecurityQualityOfService = NULL; \
}


BOOL syscall_GetRemoteProcessHandle(LPWSTR szProcessName, DWORD* dwProcessId, HANDLE* hProcess) {
	DebugPrint("[i] Using indirect syscall version of GetRemoteProcessHandle.\n");
    HANDLE hSnapShot = NULL;
    PROCESSENTRY32W	Proc = { .dwSize = sizeof(PROCESSENTRY32W) };

    NtQuerySystemInformation_t pNtQuerySystemInformation = (NtQuerySystemInformation_t)PrepareSyscallHash(NtQuerySystemInformation_JOAA);

    if (!pNtQuerySystemInformation) {
        DebugPrint("[-] Failed to prepare syscall for NtQuerySystemInformation.\n");
        return FALSE;
    }

    ULONG bufferSize = 0;
    PVOID pProcessInfo = NULL;
    NTSTATUS status = pNtQuerySystemInformation(SystemProcessInformation, pProcessInfo, 0, &bufferSize);

    if (status != STATUS_INFO_LENGTH_MISMATCH) {
        DebugPrint("[-] NtQuerySystemInformation failed: 0x%X\n", status);
        return FALSE;
    }

	NtAllocateVirtualMemory_t pNtAllocateVirtualMemory = (NtAllocateVirtualMemory_t)PrepareSyscallHash(NtAllocateVirtualMemory_JOAA);
    
    if (!pNtAllocateVirtualMemory) {
        DebugPrint("[-] Failed to prepare syscall for NtAllocateVirtualMemory.\n");
        return FALSE;
    }

    SIZE_T regionSize = bufferSize;
    status = pNtAllocateVirtualMemory(
        GetCurrentProcess(),
        &pProcessInfo,
        0,
        &regionSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );
	if (!NT_SUCCESS(status)) {
        DebugPrint("[-] NtAllocateVirtualMemory failed: 0x%X\n", status);
        return FALSE;
    }

    status = pNtQuerySystemInformation(SystemProcessInformation, pProcessInfo, bufferSize, &bufferSize);
    if (!NT_SUCCESS(status)) {
        DebugPrint("[-] NtQuerySystemInformation failed: 0x%X\n", status);
        HeapFree(GetProcessHeap(), 0, pProcessInfo);
        return FALSE;
    }

    PSYSTEM_PROCESS_INFORMATION pCurrent = (PSYSTEM_PROCESS_INFORMATION)pProcessInfo;
    while (pCurrent) {
        if (pCurrent->ImageName.Buffer && _wcsicmp(pCurrent->ImageName.Buffer, szProcessName) == 0) {
            *dwProcessId = (DWORD)(ULONG_PTR)pCurrent->UniqueProcessId;
            break;
        }
        pCurrent = (pCurrent->NextEntryOffset) ? (PSYSTEM_PROCESS_INFORMATION)((LPBYTE)pCurrent + pCurrent->NextEntryOffset) : NULL;
    }

    if (dwProcessId == NULL || *dwProcessId == 0) {
        DebugPrint("[-] Process not found.\n");
        goto _EndOfFunction;
    }

    NtOpenProcess_t pNtOpenProcess = (NtOpenProcess_t)PrepareSyscallHash(NtOpenProcess_JOAA);

    if (!pNtOpenProcess) {
        DebugPrint("[-] Failed to prepare syscall for NtOpenProcess.\n");
        return FALSE;
    }

    OBJECT_ATTRIBUTES ObjectAttributes;
    CLIENT_ID ClientId;
    InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
    ClientId.UniqueProcessId = (HANDLE)(ULONG_PTR)*dwProcessId;
    ClientId.UniqueThreadId = NULL;

    status = pNtOpenProcess(hProcess, PROCESS_ALL_ACCESS, &ObjectAttributes, &ClientId);

    if (!NT_SUCCESS(status)) {
        DebugPrint("[!] NtOpenProcess Failed With Error: 0x%X \n", status);
        return FALSE;
    }

_EndOfFunction:
    if (pProcessInfo) {
        NtFreeVirtualMemory_t pNtFreeVirtualMemory = (NtFreeVirtualMemory_t)PrepareSyscallHash(NtFreeVirtualMemory_JOAA);
        if (!pNtFreeVirtualMemory) {
            DebugPrint("[-] Failed to prepare syscall for NtFreeVirtualMemory.\n");
            return FALSE;
        }

        NTSTATUS status = pNtFreeVirtualMemory(
            GetCurrentProcess(),  // Using the current process handle
            &pProcessInfo,        // Pointer to the base address of the allocated memory
            &regionSize,          // Size of the allocated memory
            MEM_RELEASE           // Indicate we want to fully release the memory
        );
        if (!NT_SUCCESS(status)) {
            DebugPrint("[-] NtFreeVirtualMemory failed: 0x%X\n", status);
            return FALSE;
        }

	}
    
    return (*dwProcessId != NULL && *hProcess != NULL);
}

BOOL GetRemoteProcAddress(HANDLE hProcess, LPCSTR lpModuleName, LPCSTR lpProcName, PVOID* ppAddress) {
    HMODULE hMods[1024];
    DWORD cbNeeded;

    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, GetProcessId(hProcess));
    if (!hProcess) {
        DebugPrint("[!] OpenProcess failed with error: %d\n", GetLastError());
        return FALSE;
    }

    EnumProcessModules_t EnumProcessModules = (EnumProcessModules_t)GetProcAddress(LoadLibraryA("psapi"), "EnumProcessModules");
    GetModuleBaseNameA_t GetModuleBaseNameA = (GetModuleBaseNameA_t)GetProcAddress(LoadLibraryA("psapi"), "GetModuleBaseNameA");
    GetModuleInformation_t GetModuleInformation = (GetModuleInformation_t)GetProcAddress(LoadLibraryA("psapi"), "GetModuleInformation");
    if (!EnumProcessModules) {
        printf("Failed to resolve EnumProcessModules functions\n");
        return 1;
    }
    if (!GetModuleBaseNameA) {
        printf("Failed to resolve GetModuleBaseNameA functions\n");
        return 1;
    }
    if (!GetModuleInformation) {
        printf("Failed to resolve GetModuleInformation functions\n");
        return 1;
    }

    // Get the list of modules in the target process
    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        for (size_t i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            char szModuleName[MAX_PATH];
            if (GetModuleBaseNameA(hProcess, hMods[i], szModuleName, sizeof(szModuleName))) {
                DebugPrint("[i] Module: %s\n", szModuleName);
            }
            if (GetModuleBaseNameA(hProcess, hMods[i], szModuleName, sizeof(szModuleName))) {
                if (_stricmp(lpModuleName, szModuleName) == 0) {
                    // Match found; calculate remote function address
                    MODULEINFO modInfo;
                    GetModuleInformation(hProcess, hMods[i], &modInfo, sizeof(MODULEINFO));
                    DWORD_PTR baseAddr = (DWORD_PTR)modInfo.lpBaseOfDll;
                    DWORD_PTR localAddr = (DWORD_PTR)GetProcAddress(GetModuleHandleA(lpModuleName), lpProcName);
                    *ppAddress = (PVOID)(baseAddr + (localAddr - (DWORD_PTR)GetModuleHandleA(lpModuleName)));
                    return TRUE;
                }
            }
        }
    }
    else {
        DebugPrint("[!] EnumProcessModulesEx failed with error: %d\n", GetLastError());
    }
    return FALSE;
}


#ifdef _WIN64
PPEB GetPEBStealthy() {
    void* pTeb = (void*)__readgsqword(0x30); // TEB base for x64
    return *(PPEB*)((unsigned char*)pTeb + 0x60); // Offset to PEB
}
#elif _WIN32
PPEB GetPEBStealthy() {
    void* pTeb;
    __asm {
        mov eax, fs:[0x18]  // TEB base for x86
        mov pTeb, eax
    }
    return *(PPEB*)((unsigned char*)pTeb + 0x30); // Offset to PEB
}
#endif

BOOL IsHandleValid(HANDLE h) {
    DWORD flags = 0;

    // Check if handle is NULL or INVALID_HANDLE_VALUE first
    if (h == NULL || h == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    // Try to get handle information
    if (GetHandleInformation(h, &flags)) {
        return TRUE;
    }

    return FALSE;
}

wchar_t* _wcscpy(wchar_t* d, const wchar_t* s)
{
    wchar_t* a = d;
    while ((*d++ = *s++));
    return a;
}

wchar_t* _wcscat(wchar_t* dest, const wchar_t* src)
{
    _wcscpy(dest + _wcslen(dest), src);
    return dest;
}

size_t _wcslen(const wchar_t* s)
{
    const wchar_t* a;
    for (a = s; *s; s++);
    return s - a;
}
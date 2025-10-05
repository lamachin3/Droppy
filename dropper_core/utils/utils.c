#include "utils.h"
#include "../modules/stealth_techniques/api_hashing.h"

// Define function pointer types for Process32FirstW and Process32NextW
typedef BOOL (WINAPI *PProcess32FirstW)(HANDLE, LPPROCESSENTRY32W);
typedef BOOL (WINAPI *PProcess32NextW)(HANDLE, LPPROCESSENTRY32W);


BOOL GetRemoteProcessHandle(LPWSTR szProcessName, DWORD* dwProcessId, HANDLE* hProcess) {
#ifdef SYSCALL_ENABLED
    return GetRemoteProcessHandleSyscall(szProcessName, dwProcessId, hProcess);
#else
    return GetRemoteProcessHandleWinAPI(szProcessName, dwProcessId, hProcess);
#endif
}

// Gets the process handle of a process of name szProcessName
BOOL GetRemoteProcessHandleWinAPI(LPWSTR szProcessName, DWORD* dwProcessId, HANDLE* hProcess) {
	HANDLE			hSnapShot		= NULL;
	PROCESSENTRY32W	Proc;
	PPROCESSENTRY32W pProc = &Proc;
	pProc->dwSize = sizeof(PROCESSENTRY32W);

	// Takes a snapshot of the currently running processes

	hSnapShot = (HANDLE)CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hSnapShot == INVALID_HANDLE_VALUE){
		DebugPrint("[!] CreateToolhelp32Snapshot Failed With Error : %d \n", GetLastError());
		goto _EndOfFunction;
	}

	// Get Process32FirstW address using API hashing
	PProcess32FirstW pProcess32FirstW_func = (PProcess32FirstW)GetProcAddressH(GetModuleHandleH(KERNEL32DLL_JOAA), Process32FirstW_JOAA);
	if (!pProcess32FirstW_func) {
		DebugPrint("[!] Failed to get Process32FirstW address through API Hashing\n");
		pProcess32FirstW_func = (PProcess32FirstW)GetProcAddress(GetModuleHandleA("kernel32.dll"), "Process32FirstW");
		//goto _EndOfFunction;
	}

	// Retrieves information about the first process encountered in the snapshot.
	if (!pProcess32FirstW_func(hSnapShot, &Proc)) {
		DebugPrint("[!] Process32FirstW Failed With Error : %d \n", GetLastError());
		goto _EndOfFunction;
	}

	do {

		WCHAR LowerName[MAX_PATH * 2];

		DWORD	dwSize = lstrlenW(pProc->szExeFile);
		DWORD   i = 0;

		RtlSecureZeroMemory(LowerName, MAX_PATH * 2);

		// Converting each character in pProc->szExeFile to a lowercase character and saving it
		// in LowerName to do the wcscmp call later

		if (dwSize > 0 && dwSize < MAX_PATH * 2) {
			for (; i < dwSize; i++) {
				LowerName[i] = (WCHAR)tolower(pProc->szExeFile[i]);
			}
			LowerName[i] = '\0';
		}

		// Compare the enumerated process path with what is passed
		if (wcscmp(LowerName, szProcessName) == 0) {
			// Save the process ID 
			*dwProcessId	= pProc->th32ProcessID;
			// Open a process handle and return

			*hProcess		= OpenProcess(PROCESS_ALL_ACCESS, FALSE, pProc->th32ProcessID);

			if (*hProcess == NULL)
				DebugPrint("[!] OpenProcess Failed With Error : %d \n", GetLastError());

			break;
		}

		// Get Process32NextW address using API hashing (only once before the loop)
		static PProcess32NextW pProcess32NextW_func = NULL;
		if (!pProcess32NextW_func) {
			pProcess32NextW_func = (PProcess32NextW)GetProcAddressH(GetModuleHandleH(KERNEL32DLL_JOAA), Process32NextW_JOAA);
			if (!pProcess32NextW_func) {
				DebugPrint("[!] Failed to get Process32NextW address through API Hashing\n");
				pProcess32NextW_func = (PProcess32NextW)GetProcAddress(GetModuleHandleA("kernel32.dll"), "Process32NextW");
				//goto _EndOfFunction;
			}
		}

		// Continue to next process
		if (!pProcess32NextW_func(hSnapShot, pProc)) {
			break;
		}

	} while (1);

_EndOfFunction:
	if (hSnapShot != NULL) {
		CloseHandle(hSnapShot);
	}
	
	if (dwProcessId == NULL || *dwProcessId == 0 || hProcess == NULL || *hProcess == NULL) {
		return FALSE;
	}
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


BOOL GetFunctionAddressInRemoteProcess(HANDLE hProcess, LPCSTR lpFunctionName, LPCSTR lpModuleName, PVOID* pFunctionAddress) {
	HMODULE hModules[1024];
	DWORD cbNeeded;
	char szModuleName[MAX_PATH];
	*pFunctionAddress = NULL;

    HMODULE hPsapi = LoadLibraryA("psapi.dll");
    if (!hPsapi) {
        DebugPrint("Failed to load psapi.dll. Error: %ld\n", GetLastError());
        return 0;
    }

    EnumProcessModulesEx_t pEnumProcessModulesEx = (EnumProcessModulesEx_t)GetProcAddress(hPsapi, "EnumProcessModulesEx");
	GetModuleBaseNameA_t pGetModuleBaseNameA = (GetModuleBaseNameA_t)GetProcAddress(hPsapi, "GetModuleBaseNameA");

	if (pEnumProcessModulesEx(hProcess, hModules, sizeof(hModules), &cbNeeded, LIST_MODULES_ALL)) {
		for (int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
			if (pGetModuleBaseNameA(hProcess, hModules[i], szModuleName, sizeof(szModuleName) / sizeof(char))) {
				if (_stricmp(szModuleName, lpModuleName) == 0) {
					HMODULE hLocalModule = GetModuleHandleA(lpModuleName);
					if (hLocalModule != NULL) {
						PVOID pLocalAddress = (PVOID)GetProcAddress(hLocalModule, lpFunctionName);
						*pFunctionAddress = (PVOID)((BYTE*)hModules[i] + ((BYTE*)pLocalAddress - (BYTE*)hLocalModule));
						return TRUE;
					}
				}
			}
		}
	}
	else {
		DebugPrint("[X] EnumProcessModulesEx failed with error: %ld\n", GetLastError());
	}
	return FALSE;
}

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
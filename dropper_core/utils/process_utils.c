#include "process_utils.h"

#define BUFSIZE 4096

BOOL AttachRemoteProcessOutput(HANDLE* hStdOutRead, HANDLE* hStdOutWrite, SECURITY_ATTRIBUTES* saAttr) {
    if (!CreatePipe(hStdOutRead, hStdOutWrite, saAttr, 0)) {
        DebugPrint("[!] CreatePipe failed with error: %d\n", GetLastError());
        return FALSE;
    }

    if (!SetHandleInformation(*hStdOutRead, HANDLE_FLAG_INHERIT, 0)) {
        DebugPrint("[!] SetHandleInformation failed with error: %d\n", GetLastError());
        CloseHandle(*hStdOutRead);
        CloseHandle(*hStdOutWrite);
        return FALSE;
    }

    return TRUE;
}

void ReadFromRemotePipe(HANDLE hStdOutRead) {
    HANDLE hParentStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
    CHAR chBuf[BUFSIZE];
    DWORD dwRead, dwWritten;
    DWORD dwAvailable;
    BOOL bSuccess;

    int noDataCounter = 0;

    while (TRUE) {
        if (!PeekNamedPipe(hStdOutRead, NULL, 0, NULL, &dwAvailable, NULL)) {
            DebugPrint("[!] PeekNamedPipe failed.\n");
            break;
        }

        if (dwAvailable > 0) {
            noDataCounter = 0;

            bSuccess = ReadFile(hStdOutRead, chBuf, BUFSIZE, &dwRead, NULL);
            if (!bSuccess || dwRead == 0) {
                DebugPrint("[!] ReadFile failed or no bytes read.\n");
                break;
            }

            bSuccess = WriteFile(hParentStdOut, chBuf, dwRead, &dwWritten, NULL);
            if (!bSuccess) {
                DebugPrint("[!] WriteFile failed.\n");
                break;
            }
        }
        else {
            noDataCounter++;
            if (noDataCounter >= 10) {
                DebugPrint("[!] No more data available. Exiting stdout pipe...\n");
                break;
            }
            Sleep(500);
        }
    }
}

/*
Parameters:
	- lpProcessName; a process name under '\System32\' to create
	- dwProcessId;  Pointer to a DWORD which will recieve the newly created process's PID.
	- hProcess; Pointer to a HANDLE that will recieve the newly created process's handle.
	- hThread; Pointer to a HANDLE that will recieve the newly created process's thread.

Creates a new process 'lpProcessName' in suspended state and return its pid, handle, and the handle of its main thread
*/
BOOL CreateSuspendedProcess(LPWSTR lpProcessName, DWORD* dwProcessId, HANDLE* hProcess, HANDLE* hThread, HANDLE hStdOutput, HANDLE hStdError) {
    WCHAR lpPath[MAX_PATH * 2];
    WCHAR WnDr[MAX_PATH];

    STARTUPINFOW Si = { 0 };
    PROCESS_INFORMATION Pi = { 0 };

    // Cleaning the structs
    RtlSecureZeroMemory(&Si, sizeof(STARTUPINFOW));
    RtlSecureZeroMemory(&Pi, sizeof(PROCESS_INFORMATION));

    // Setting the size of the structure
    Si.cb = sizeof(STARTUPINFOW);
	Si.hStdError = hStdOutput;
	Si.hStdOutput = hStdError;
	Si.dwFlags |= STARTF_USESTDHANDLES;

    // Creating the target process path
    wcscpy_s(lpPath, MAX_PATH * 2, lpProcessName);
    DebugPrint("\n\t[i] Running : \"%ls\" ...\n", lpPath);

    if (!CreateProcessW(
        NULL,
        lpPath,
        NULL,
        NULL,
        TRUE,
        CREATE_SUSPENDED,  // alt: DEBUG_PROCESS
        NULL,
        NULL,
        &Si,
        &Pi)) {
        DebugPrint("[!] CreateProcessW Failed with Error : %d \n", GetLastError());
        return FALSE;
    }

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
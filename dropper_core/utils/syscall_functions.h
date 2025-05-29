#ifndef SYSCALL_FUNCTIONS_H
#define SYSCALL_FUNCTIONS_H

#include "../common.h"

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif

BOOL CreateSuspendedProcessSyscall(PWSTR pwProcessPath, PROCESS_INFORMATION* pPi, HANDLE hStdOutput, HANDLE hStdError);
BOOL GetRemoteProcessHandleSyscall(LPWSTR szProcessName, DWORD* dwProcessId, HANDLE* hProcess);

#endif
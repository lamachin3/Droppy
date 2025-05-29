#ifndef PROCESS_UTILS_H
#define PROCESS_UTILS_H

#include "../common.h"

BOOL AttachRemoteProcessOutput(HANDLE* hStdOutRead, HANDLE* hStdOutWrite, SECURITY_ATTRIBUTES* saAttr);
void ReadFromRemotePipe(HANDLE hStdOutRead);
BOOL CreateRunningProcess(LPWSTR lpProcessName, DWORD* dwProcessId, HANDLE* hProcess, HANDLE* hThread, HANDLE hStdOutput, HANDLE hStdError);
BOOL CreateSuspendedProcess(LPWSTR lpProcessName, OUT PROCESS_INFORMATION* pPi, HANDLE hStdOutput, HANDLE hStdError);

#endif
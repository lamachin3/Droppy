#ifndef PROCESS_UTILS_H
#define PROCESS_UTILS_H

#include "../common.h"

BOOL AttachRemoteProcessOutput(HANDLE* hStdOutRead, HANDLE* hStdOutWrite, SECURITY_ATTRIBUTES* saAttr);
void ReadFromRemotePipe(HANDLE hStdOutRead);
BOOL CreateSuspendedProcess(LPWSTR lpProcessName, DWORD* dwProcessId, HANDLE* hProcess, HANDLE* hThread, HANDLE hStdOutput, HANDLE hStdError);

#endif
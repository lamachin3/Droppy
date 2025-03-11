#ifndef UTILS_H
#define UTILS_H

#include "../common.h"

BOOL GetRemoteProcessHandle(LPWSTR szProcessName, DWORD* dwProcessId, HANDLE* hProcess);

#endif
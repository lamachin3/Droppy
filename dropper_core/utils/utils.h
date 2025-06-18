#ifndef UTILS_H
#define UTILS_H

#include "../common.h"

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif

BOOL GetRemoteProcessHandle(LPWSTR szProcessName, DWORD* dwProcessId, HANDLE* hProcess);
BOOL GetFunctionAddressInRemoteProcess(HANDLE hProcess, LPCSTR lpFunctionName, LPCSTR lpModuleName, PVOID* pFunctionAddress);
BOOL IsHandleValid(HANDLE h);
wchar_t* _wcscpy(wchar_t* d, const wchar_t* s);
wchar_t* _wcscat(wchar_t* dest, const wchar_t* src);
size_t _wcslen(const wchar_t* s);

#endif
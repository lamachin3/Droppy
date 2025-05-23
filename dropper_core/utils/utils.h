#ifndef UTILS_H
#define UTILS_H

#include "../common.h"

BOOL GetRemoteProcessHandle(LPWSTR szProcessName, DWORD* dwProcessId, HANDLE* hProcess);
BOOL FetchEnvironmentVariable(LPCWSTR lpName, LPWSTR lpBuffer, DWORD nSize);
BOOL GetFunctionAddressInRemoteProcess(HANDLE hProcess, LPCSTR lpFunctionName, LPCSTR lpModuleName, PVOID* pFunctionAddress);
PPEB GetPEBStealthy();
BOOL IsHandleValid(HANDLE h);
wchar_t* _wcscpy(wchar_t* d, const wchar_t* s);
wchar_t* _wcscat(wchar_t* dest, const wchar_t* src);
size_t _wcslen(const wchar_t* s);

#endif
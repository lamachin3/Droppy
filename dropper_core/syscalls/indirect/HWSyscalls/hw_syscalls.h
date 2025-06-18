#pragma once
#include "../../../common.h"

#pragma region Defines

#define HWSYSCALLS_DEBUG 1 // 0 disable, 1 enable
#define UP -32
#define DOWN 32
#define STACK_ARGS_LENGTH 8
#define STACK_ARGS_RSP_OFFSET 0x28
#define X64_PEB_OFFSET 0x60

#pragma endregion

#pragma region Type Defintions

typedef BOOL(WINAPI* GetThreadContext_t)(
    _In_ HANDLE hThread,
    _Inout_ LPCONTEXT lpContext
    );

typedef BOOL(WINAPI* SetThreadContext_t)(
    _In_ HANDLE hThread,
    _In_ CONST CONTEXT* lpContext
    );  

#pragma endregion

#pragma region Function Declerations

BOOL MaskCompare(const BYTE* pData, const BYTE* bMask, const char* szMask);
DWORD_PTR FindPattern(DWORD_PTR dwAddress, DWORD dwLen, PBYTE bMask, PCHAR szMask);
DWORD_PTR FindInModule(LPCSTR moduleName, PBYTE bMask, PCHAR szMask);
UINT64 GetModuleAddress(LPWSTR sModuleName);
UINT64 GetSymbolAddress(UINT64 moduleBase, const char* functionName);
UINT64 PrepareSyscall(char* functionName);
UINT64 PrepareSyscallHash(UINT32 functionHash);
BOOL SetMainBreakpoint();
DWORD64 FindSyscallNumber(DWORD64 functionAddress);
DWORD64 FindSyscallReturnAddress(DWORD64 functionAddress, WORD syscallNumber);
LONG HWSyscallExceptionHandler(EXCEPTION_POINTERS* ExceptionInfo);
BOOL InitHWSyscalls();
BOOL DeinitHWSyscalls();

#pragma endregion

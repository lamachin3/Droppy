
#pragma once

#include <windows.h>

//----------------------------------------
// Section: Basic Type Aliases
//----------------------------------------
typedef long            NTSTATUS;
typedef unsigned long   ULONG;
typedef void*           PVOID;
typedef unsigned char   BYTE;
typedef int             BOOL;

#ifndef _WINDEF_
typedef unsigned long   DWORD;
#endif

//----------------------------------------
// Section: Common Constants
//----------------------------------------
#define TRUE  1
#define FALSE 0
#define MAX_BUFFER_SIZE 1024
#define RTL_MAX_DRIVE_LETTERS 32
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

//----------------------------------------
// Section: Object & Process Constants
//----------------------------------------
#define ProcessBasicInformation               0
#define RTL_USER_PROC_PARAMS_NORMALIZED       0x00000001
#define OBJ_CASE_INSENSITIVE                  0x00000040L
#define THREAD_CREATE_FLAGS_CREATE_SUSPENDED  0x00000001

// Self handle
#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)

//----------------------------------------
// TlHelp32 Constants
//----------------------------------------
#define TH32CS_SNAPPROCESS      0x2
#define TH32CS_SNAPMODULE       0x00000008
#define TH32CS_SNAPMODULE32     0x00000010
#define MAX_MODULE_NAME32       255

HANDLE WINAPI CreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID);

//----------------------------------------
// Hardware Breakpoint Constants
//----------------------------------------
#define ALL_THREADS		0x00
// Get Parameters
#define GETPARM_1(CTX)(GetFunctionArgument(CTX, 0x1))	
#define GETPARM_2(CTX)(GetFunctionArgument(CTX, 0x2))
#define GETPARM_3(CTX)(GetFunctionArgument(CTX, 0x3))
#define GETPARM_4(CTX)(GetFunctionArgument(CTX, 0x4))
#define GETPARM_5(CTX)(GetFunctionArgument(CTX, 0x5))
#define GETPARM_6(CTX)(GetFunctionArgument(CTX, 0x6))
#define GETPARM_7(CTX)((ULONG)GetFunctionArgument(CTX, 0x7))
#define GETPARM_8(CTX)(GetFunctionArgument(CTX, 0x8))
#define GETPARM_9(CTX)(GetFunctionArgument(CTX, 0x9))
#define GETPARM_A(CTX)(GetFunctionArgument(CTX, 0xA))
#define GETPARM_B(CTX)(GetFunctionArgument(CTX, 0xB))

// Set Parameters
#define SETPARM_1(CTX, VALUE)(SetFunctionArgument(CTX, VALUE, 0x1))
#define SETPARM_2(CTX, VALUE)(SetFunctionArgument(CTX, VALUE, 0x2))
#define SETPARM_3(CTX, VALUE)(SetFunctionArgument(CTX, VALUE, 0x3))
#define SETPARM_4(CTX, VALUE)(SetFunctionArgument(CTX, VALUE, 0x4))
#define SETPARM_5(CTX, VALUE)(SetFunctionArgument(CTX, VALUE, 0x5))
#define SETPARM_6(CTX, VALUE)(SetFunctionArgument(CTX, VALUE, 0x6))
#define SETPARM_7(CTX, VALUE)(SetFunctionArgument(CTX, VALUE, 0x7))
#define SETPARM_8(CTX, VALUE)(SetFunctionArgument(CTX, VALUE, 0x8))
#define SETPARM_9(CTX, VALUE)(SetFunctionArgument(CTX, VALUE, 0x9))
#define SETPARM_A(CTX, VALUE)(SetFunctionArgument(CTX, VALUE, 0xA))
#define SETPARM_B(CTX, VALUE)(SetFunctionArgument(CTX, VALUE, 0xB))

//----------------------------------------
// Section: Process Attribute Macros
//----------------------------------------
#define PS_ATTRIBUTE_NUMBER_MASK 0x0000ffff
#define PS_ATTRIBUTE_THREAD      0x00010000
#define PS_ATTRIBUTE_INPUT       0x00020000
#define PS_ATTRIBUTE_ADDITIVE    0x00040000

#define PsAttributeValue(Number, Thread, Input, Additive) \
    (((Number) & PS_ATTRIBUTE_NUMBER_MASK)               \
     | ((Thread)   ? PS_ATTRIBUTE_THREAD   : 0)          \
     | ((Input)    ? PS_ATTRIBUTE_INPUT    : 0)          \
     | ((Additive) ? PS_ATTRIBUTE_ADDITIVE : 0))

#define PS_ATTRIBUTE_PARENT_PROCESS            PsAttributeValue(PsAttributeParentProcess, FALSE, TRUE,  TRUE)
#define PS_ATTRIBUTE_DEBUG_PORT                PsAttributeValue(PsAttributeDebugPort,       FALSE, TRUE,  TRUE)
#define PS_ATTRIBUTE_TOKEN                     PsAttributeValue(PsAttributeToken,            FALSE, TRUE,  TRUE)
#define PS_ATTRIBUTE_CLIENT_ID                 PsAttributeValue(PsAttributeClientId,        TRUE,  FALSE, FALSE)
#define PS_ATTRIBUTE_TEB_ADDRESS               PsAttributeValue(PsAttributeTebAddress,      TRUE,  FALSE, FALSE)
#define PS_ATTRIBUTE_IMAGE_NAME                PsAttributeValue(PsAttributeImageName,       FALSE, TRUE,  FALSE)
#define PS_ATTRIBUTE_IMAGE_INFO                PsAttributeValue(PsAttributeImageInfo,       FALSE, FALSE, FALSE)
#define PS_ATTRIBUTE_MEMORY_RESERVE            PsAttributeValue(PsAttributeMemoryReserve,   FALSE, TRUE,  FALSE)
#define PS_ATTRIBUTE_PRIORITY_CLASS            PsAttributeValue(PsAttributePriorityClass,   FALSE, TRUE,  FALSE)
#define PS_ATTRIBUTE_ERROR_MODE                PsAttributeValue(PsAttributeErrorMode,       FALSE, TRUE,  FALSE)
#define PS_ATTRIBUTE_STD_HANDLE_INFO           PsAttributeValue(PsAttributeStdHandleInfo,   FALSE, TRUE,  FALSE)
#define PS_ATTRIBUTE_HANDLE_LIST               PsAttributeValue(PsAttributeHandleList,      FALSE, TRUE,  FALSE)
#define PS_ATTRIBUTE_GROUP_AFFINITY            PsAttributeValue(PsAttributeGroupAffinity,   TRUE,  TRUE,  FALSE)
#define PS_ATTRIBUTE_PREFERRED_NODE            PsAttributeValue(PsAttributePreferredNode,   FALSE, TRUE,  FALSE)
#define PS_ATTRIBUTE_IDEAL_PROCESSOR           PsAttributeValue(PsAttributeIdealProcessor,  TRUE,  TRUE,  FALSE)
#define PS_ATTRIBUTE_MITIGATION_OPTIONS        PsAttributeValue(PsAttributeMitigationOptions,FALSE, TRUE,  FALSE)
#define PS_ATTRIBUTE_PROTECTION_LEVEL          PsAttributeValue(PsAttributeProtectionLevel, FALSE, TRUE,  FALSE)
#define PS_ATTRIBUTE_UMS_THREAD                PsAttributeValue(PsAttributeUmsThread,       TRUE,  TRUE,  FALSE)
#define PS_ATTRIBUTE_SECURE_PROCESS            PsAttributeValue(PsAttributeSecureProcess,   FALSE, TRUE,  FALSE)
#define PS_ATTRIBUTE_JOB_LIST                  PsAttributeValue(PsAttributeJobList,         FALSE, TRUE,  FALSE)
#define PS_ATTRIBUTE_CHILD_PROCESS_POLICY      PsAttributeValue(PsAttributeChildProcessPolicy,FALSE,TRUE, FALSE)
#define PS_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY \
    PsAttributeValue(PsAttributeAllApplicationPackagesPolicy, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_WIN32K_FILTER             PsAttributeValue(PsAttributeWin32kFilter,    FALSE, TRUE,  FALSE)
#define PS_ATTRIBUTE_SAFE_OPEN_PROMPT_ORIGIN_CLAIM \
    PsAttributeValue(PsAttributeSafeOpenPromptOriginClaim, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_BNO_ISOLATION             PsAttributeValue(PsAttributeBnoIsolation,    FALSE, TRUE,  FALSE)
#define PS_ATTRIBUTE_DESKTOP_APP_POLICY        PsAttributeValue(PsAttributeDesktopAppPolicy,FALSE, TRUE,  FALSE)

//----------------------------------------
// Section: Process Creation Flags
//----------------------------------------
#define PROCESS_CREATE_FLAGS_BREAKAWAY            0x00000001
#define PROCESS_CREATE_FLAGS_NO_DEBUG_INHERIT     0x00000002
#define PROCESS_CREATE_FLAGS_INHERIT_HANDLES      0x00000004
#define PROCESS_CREATE_FLAGS_PROTECTED_PROCESS    0x00000040
#define PROCESS_CREATE_FLAGS_CREATE_SESSION       0x00000080
#define PROCESS_CREATE_FLAGS_INHERIT_FROM_PARENT  0x00000100
#define PROCESS_CREATE_FLAGS_SUSPENDED            0x00000200
#define PROCESS_CREATE_FLAGS_FORCE_BREAKAWAY      0x00000400
#define PROCESS_CREATE_FLAGS_RELEASE_SECTION      0x00001000
#define PROCESS_CREATE_FLAGS_AUXILIARY_PROCESS    0x00008000
#define PROCESS_CREATE_FLAGS_CREATE_STORE         0x00020000
#define PROCESS_CREATE_FLAGS_USE_PROTECTED_ENVIRONMENT 0x00040000

//----------------------------------------
// Section: RTL User Process Flags
//----------------------------------------
#define RTL_USER_PROC_PROFILE_USER           0x00000002
#define RTL_USER_PROC_PROFILE_KERNEL         0x00000004
#define RTL_USER_PROC_PROFILE_SERVER         0x00000008
#define RTL_USER_PROC_RESERVE_1MB            0x00000020
#define RTL_USER_PROC_RESERVE_16MB           0x00000040
#define RTL_USER_PROC_CASE_SENSITIVE         0x00000080
#define RTL_USER_PROC_DISABLE_HEAP_DECOMMIT  0x00000100
#define RTL_USER_PROC_DLL_REDIRECTION_LOCAL  0x00001000
#define RTL_USER_PROC_APP_MANIFEST_PRESENT   0x00002000
#define RTL_USER_PROC_IMAGE_KEY_MISSING      0x00004000
#define RTL_USER_PROC_OPTIN_PROCESS          0x00020000

#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes(p, n, a, r, s) { \
    (p)->Length                    = sizeof(OBJECT_ATTRIBUTES); \
    (p)->RootDirectory             = r;                           \
    (p)->Attributes                = a;                           \
    (p)->ObjectName                = n;                           \
    (p)->SecurityDescriptor        = s;                           \
    (p)->SecurityQualityOfService  = NULL;                        \
}
#endif

// https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-gettickcount64
typedef ULONGLONG(WINAPI* fnGetTickCount64)();

// https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
typedef HANDLE(WINAPI* fnOpenProcess)(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);

// https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-callnexthookex
typedef LRESULT(WINAPI* fnCallNextHookEx)(HHOOK hhk, int nCode, WPARAM wParam, LPARAM lParam);

// https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setwindowshookexw
typedef HHOOK(WINAPI* fnSetWindowsHookExW)(int idHook, HOOKPROC lpfn, HINSTANCE hmod, DWORD dwThreadId);

// https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getmessagew
typedef BOOL(WINAPI* fnGetMessageW)(LPMSG lpMsg, HWND hWnd, UINT wMsgFilterMin, UINT wMsgFilterMax);

// https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-defwindowprocw
typedef LRESULT(WINAPI* fnDefWindowProcW)(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);

// https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-unhookwindowshookex
typedef BOOL(WINAPI* fnUnhookWindowsHookEx)(HHOOK hhk);

// https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulefilenamew
typedef DWORD(WINAPI* fnGetModuleFileNameW)(HMODULE hModule, LPWSTR lpFilename, DWORD nSize);

// https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew
typedef HANDLE(WINAPI* fnCreateFileW)(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);

// https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-setfileinformationbyhandle
typedef BOOL(WINAPI* fnSetFileInformationByHandle)(HANDLE hFile, FILE_INFO_BY_HANDLE_CLASS FileInformationClass, LPVOID lpFileInformation, DWORD dwBufferSize);

// https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle
typedef BOOL(WINAPI* fnCloseHandle)(HANDLE hObject);

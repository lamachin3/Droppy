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


BOOL CreateSuspendedProcessWithSyscall(IN PWSTR pwProcessName, OUT PROCESS_INFORMATION* pPi) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        printf("[!] Failed to load ntdll.dll.\n");
        return 1;
    }

    NtCreateUserProcess_t NtCreateUserProcess = (NtCreateUserProcess_t)PrepareSyscall((char *)("NtCreateUserProcess"));
    tRtlAllocateHeap RtlAllocateHeap = (tRtlAllocateHeap)GetProcAddress(hNtdll, "RtlAllocateHeap");
    tRtlDestroyProcessParameters RtlDestroyProcessParameters = (tRtlDestroyProcessParameters)GetProcAddress(hNtdll, "RtlDestroyProcessParameters");
    tRtlCreateProcessParametersEx RtlCreateProcessParametersEx = (tRtlCreateProcessParametersEx)GetProcAddress(hNtdll, "RtlCreateProcessParametersEx");

    const wchar_t* basePath = L"C:\\Windows\\System32\\";
    size_t totalLength = _wcslen(basePath) + _wcslen(pwProcessName) + 1;

    // Allocate memory for the combined string
    PWSTR pwProcessPath = (PWSTR)malloc(totalLength * sizeof(wchar_t));
    if (!pwProcessPath) {
        wprintf(L"Memory allocation failed.\n");
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
        PROCESS_CREATE_FLAGS_SUSPENDED,
        THREAD_CREATE_FLAGS_CREATE_SUSPENDED,
        ProcessParameters,
        &CreateInfo,
        pAttributeList
    );

    if (!NT_SUCCESS(status)) {
        printf("[!] Process creation failed with status: 0x%X\n", status);
        RtlDestroyProcessParameters(ProcessParameters);
        return FALSE;
    }

    pPi->hProcess = hProcess;
    pPi->hThread = hThread;
    pPi->dwProcessId = GetProcessId(hProcess);
    pPi->dwThreadId = GetThreadId(hThread);

    printf("[+] Process created successfully in a suspended state.\n");
    RtlDestroyProcessParameters(ProcessParameters);

    return TRUE;
}
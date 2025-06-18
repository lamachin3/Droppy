#include "router.h"

NTSTATUS NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength) {
    DebugPrint("[i] Calling NtQuerySystemInformation");
#if defined(SW3_SYSCALLS)
    return Sw3NtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
#elif defined(HW_SYSCALLS)
    NtQuerySystemInformation_t pNtQuerySystemInformation = (NtQuerySystemInformation_t)PrepareSyscallHash(NtQuerySystemInformation_JOAA);
    if (!pNtQuerySystemInformation) {
        return FALSE;
    }
    return pNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
#endif
}

NTSTATUS NtCreateSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle){
    DebugPrint("[i] Calling NtCreateSection");
#if defined(SW3_SYSCALLS)
    return Sw3NtCreateSection(SectionHandle, DesiredAccess, ObjectAttributes, MaximumSize, SectionPageProtection, AllocationAttributes, FileHandle);
#elif defined(HW_SYSCALLS)
    NtCreateSection_t pNtCreateSection = (NtCreateSection_t)PrepareSyscallHash(NtCreateSection_JOAA);
    if (!pNtCreateSection) {
        return FALSE;
    }
    return pNtCreateSection(SectionHandle, DesiredAccess, ObjectAttributes, MaximumSize, SectionPageProtection, AllocationAttributes, FileHandle);
#endif
}

NTSTATUS NtMapViewOfSection(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, ULONG ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, DWORD InheritDisposition, ULONG AllocationType, ULONG Protect){
    DebugPrint("[i] Calling NtMapViewOfSection");
#if defined(SW3_SYSCALLS)
    return  Sw3NtMapViewOfSection(SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Protect);
#elif defined(HW_SYSCALLS)
    NtMapViewOfSection_t pNtMapViewOfSection = (NtMapViewOfSection_t)PrepareSyscallHash(NtMapViewOfSection_JOAA);
    if (!pNtMapViewOfSection) {
        return FALSE;
    }
    return pNtMapViewOfSection(SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Protect);
#endif
}

NTSTATUS NtUnmapViewOfSection(HANDLE ProcessHandle, PVOID BaseAddress){
    DebugPrint("[i] Calling NtUnmapViewOfSection");
#if defined(SW3_SYSCALLS)
    return Sw3NtUnmapViewOfSection(ProcessHandle, BaseAddress);
#elif defined(HW_SYSCALLS)
    NtUnmapViewOfSection_t pNtUnmapViewOfSection = (NtUnmapViewOfSection_t)PrepareSyscallHash(NtUnmapViewOfSection_JOAA);
    if (!pNtUnmapViewOfSection) {
        return FALSE;
    }
    return pNtUnmapViewOfSection(ProcessHandle, BaseAddress);
#endif
}

NTSTATUS NtClose(HANDLE ObjectHandle){
    DebugPrint("[i] Calling NtClose");
#if defined(SW3_SYSCALLS)
    return Sw3NtClose(ObjectHandle);
#elif defined(HW_SYSCALLS)
    NtClose_t pNtClose = (NtClose_t)PrepareSyscallHash(NtClose_JOAA);
    if (!pNtClose) {
        return FALSE;
    }
    return pNtClose(ObjectHandle);
#endif
}

NTSTATUS NtCreateThreadEx(PHANDLE hThread, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, PVOID lpStartAddress, PVOID lpParameter, ULONG Flags, SIZE_T StackZeroBits, SIZE_T SizeOfStackCommit, SIZE_T SizeOfStackReserve, PVOID lpBytesBuffer){
    DebugPrint("[i] Calling NtCreateThreadEx");
#if defined(SW3_SYSCALLS)
    return Sw3NtCreateThreadEx(hThread, DesiredAccess, ObjectAttributes, ProcessHandle, lpStartAddress, lpParameter, Flags, StackZeroBits, SizeOfStackCommit, SizeOfStackReserve, lpBytesBuffer);
#elif defined(HW_SYSCALLS)
    NtCreateThreadEx_t pNtCreateThreadEx = (NtCreateThreadEx_t)PrepareSyscallHash(NtCreateThreadEx_JOAA);
    if (!pNtCreateThreadEx) {
        return FALSE;
    }
    return pNtCreateThreadEx(hThread, DesiredAccess, ObjectAttributes, ProcessHandle, lpStartAddress, lpParameter, Flags, StackZeroBits, SizeOfStackCommit, SizeOfStackReserve, lpBytesBuffer);
#endif
}

NTSTATUS NtWaitForSingleObject(HANDLE ObjectHandle, BOOLEAN Alertable, PLARGE_INTEGER TimeOut){
    DebugPrint("[i] Calling NtWaitForSingleObject");
#if defined(SW3_SYSCALLS)
    return Sw3NtWaitForSingleObject(ObjectHandle, Alertable, TimeOut);
#elif defined(HW_SYSCALLS)
    NtWaitForSingleObject_t pNtWaitForSingleObject = (NtWaitForSingleObject_t)PrepareSyscallHash(NtWaitForSingleObject_JOAA);
    if (!pNtWaitForSingleObject) {
        return FALSE;
    }
    return pNtWaitForSingleObject(ObjectHandle, Alertable, TimeOut);
#endif
}

NTSTATUS NtDelayExecution(BOOLEAN Alertable, PLARGE_INTEGER DelayInterval){
    DebugPrint("[i] Calling NtDelayExecution");
#if defined(SW3_SYSCALLS)
    return Sw3NtDelayExecution(Alertable, DelayInterval);
#elif defined(HW_SYSCALLS)
    NtDelayExecution_t pNtDelayExecution = (NtDelayExecution_t)PrepareSyscallHash(NtDelayExecution_JOAA);
    if (!pNtDelayExecution) {
        return FALSE;
    }
    return pNtDelayExecution(Alertable, DelayInterval);
#endif
}

NTSTATUS NtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect){
    DebugPrint("[i] Calling NtAllocateVirtualMemory");
#if defined(SW3_SYSCALLS)
    return Sw3NtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
#elif defined(HW_SYSCALLS)
    NtAllocateVirtualMemory_t pNtAllocateVirtualMemory = (NtAllocateVirtualMemory_t)PrepareSyscallHash(NtAllocateVirtualMemory_JOAA);
    if (!pNtAllocateVirtualMemory) {
        return FALSE;
    }
    return pNtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
#endif
}

NTSTATUS NtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten){
    DebugPrint("[i] Calling NtWriteVirtualMemory");
#if defined(SW3_SYSCALLS)
    return Sw3NtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);
#elif defined(HW_SYSCALLS)
    NtWriteVirtualMemory_t pNtWriteVirtualMemory = (NtWriteVirtualMemory_t)PrepareSyscallHash(NtWriteVirtualMemory_JOAA);
    if (!pNtWriteVirtualMemory) {
        return FALSE;
    }
    return pNtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);
#endif
}

NTSTATUS NtProtectVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress, PSIZE_T NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection){
    DebugPrint("[i] Calling NtProtectVirtualMemory");
#if defined(SW3_SYSCALLS)
    return Sw3NtProtectVirtualMemory(ProcessHandle, BaseAddress, NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection);
#elif defined(HW_SYSCALLS)
    NtProtectVirtualMemory_t pNtProtectVirtualMemory = (NtProtectVirtualMemory_t)PrepareSyscallHash(NtProtectVirtualMemory_JOAA);
    if (!pNtProtectVirtualMemory) {
        return FALSE;
    }
    return pNtProtectVirtualMemory(ProcessHandle, BaseAddress, NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection);
#endif
}

NTSTATUS NtFreeVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress, PSIZE_T RegionSize, ULONG FreeType){
    DebugPrint("[i] Calling NtFreeVirtualMemory");
#if defined(SW3_SYSCALLS)
    return Sw3NtFreeVirtualMemory(ProcessHandle, BaseAddress, RegionSize, FreeType);
#elif defined(HW_SYSCALLS)
    NtFreeVirtualMemory_t pNtFreeVirtualMemory = (NtFreeVirtualMemory_t)PrepareSyscallHash(NtFreeVirtualMemory_JOAA);
    if (!pNtFreeVirtualMemory) {
        return FALSE;
    }
    return pNtFreeVirtualMemory(ProcessHandle, BaseAddress, RegionSize, FreeType);
#endif
}

NTSTATUS NtQueueApcThread(HANDLE ThreadHandle, PIO_APC_ROUTINE ApcRoutine, PVOID ApcRoutineContext, PIO_STATUS_BLOCK ApcStatusBlock, ULONG ApcReserved){
    DebugPrint("[i] Calling NtQueueApcThread");
#if defined(SW3_SYSCALLS)
    return Sw3NtQueueApcThread(ThreadHandle, (PKNORMAL_ROUTINE)ApcRoutine, ApcRoutineContext, ApcStatusBlock, (PVOID)ApcReserved);
#elif defined(HW_SYSCALLS)
    NtQueueApcThread_t pNtQueueApcThread = (NtQueueApcThread_t)PrepareSyscallHash(NtQueueApcThread_JOAA);
    if (!pNtQueueApcThread) {
        return FALSE;
    }
    return pNtQueueApcThread(ThreadHandle, ApcRoutine, ApcRoutineContext, ApcStatusBlock, ApcReserved);
#endif
}

NTSTATUS NtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID  ClientId){
    DebugPrint("[i] Calling NtOpenProcess");
#if defined(SW3_SYSCALLS)
    return Sw3NtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
#elif defined(HW_SYSCALLS)
    NtOpenProcess_t pNtOpenProcess = (NtOpenProcess_t)PrepareSyscallHash(NtOpenProcess_JOAA);
    if (!pNtOpenProcess) {
        return FALSE;
    }
    return pNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
#endif
}

NTSTATUS NtOpenSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes){
    DebugPrint("[i] Calling NtOpenSection");
#if defined(SW3_SYSCALLS)
    return Sw3NtOpenSection(SectionHandle, DesiredAccess, ObjectAttributes);
#elif defined(HW_SYSCALLS)
    NtOpenSection_t pNtOpenSection = (NtOpenSection_t)PrepareSyscallHash(NtOpenSection_JOAA);
    if (!pNtOpenSection) {
        return FALSE;
    }
    return pNtOpenSection(SectionHandle, DesiredAccess, ObjectAttributes);
#endif
}

NTSTATUS NtResumeThread(HANDLE ThreadHandle, PULONG SuspendCount) {
    DebugPrint("[i] Calling NtResumeThread");
#if defined(SW3_SYSCALLS)
    return Sw3NtResumeThread(ThreadHandle, SuspendCount);
#elif defined(HW_SYSCALLS)
    NtResumeThread_t pNtResumeThread = (NtResumeThread_t)PrepareSyscallHash(NtResumeThread_JOAA);
    if (!pNtResumeThread) {
        return FALSE;
    }
    return pNtResumeThread(ThreadHandle, SuspendCount);
#endif
}

NTSTATUS NtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToRead, PSIZE_T NumberOfBytesReaded) {
    DebugPrint("[i] Calling NtReadVirtualMemory");
#if defined(SW3_SYSCALLS)
    return Sw3NtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesReaded);
#elif defined(HW_SYSCALLS)
    NtReadVirtualMemory_t pNtReadVirtualMemory = (NtReadVirtualMemory_t)PrepareSyscallHash(NtReadVirtualMemory_JOAA);
    if (!pNtReadVirtualMemory) {
        return FALSE;
    }
    return pNtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesReaded);
#endif
}

NTSTATUS NtCreateUserProcess(PHANDLE ProcessHandle, PHANDLE ThreadHandle, ACCESS_MASK ProcessDesiredAccess, ACCESS_MASK ThreadDesiredAccess, POBJECT_ATTRIBUTES ProcessObjectAttributes, POBJECT_ATTRIBUTES ThreadObjectAttributes, ULONG ProcessFlags, ULONG ThreadFlags, PRTL_USER_PROCESS_PARAMETERS ProcessParameters, PPS_CREATE_INFO CreateInfo, PPS_ATTRIBUTE_LIST pAttributeList) {
    DebugPrint("[i] Calling NtCreateUserProcess\n");
#if defined(SW3_SYSCALLS)
    return Sw3NtCreateUserProcess(ProcessHandle, ThreadHandle, ProcessDesiredAccess, ThreadDesiredAccess, ProcessObjectAttributes, ThreadObjectAttributes, ProcessFlags, ThreadFlags, ProcessParameters, CreateInfo, pAttributeList);
#elif defined(HW_SYSCALLS)
    NtCreateUserProcess_t pNtCreateUserProcess = (NtCreateUserProcess_t)PrepareSyscallHash(NtCreateUserProcess_JOAA);
    if (!pNtCreateUserProcess) {
        return FALSE;
    }
    return pNtCreateUserProcess(ProcessHandle, ThreadHandle, ProcessDesiredAccess, ThreadDesiredAccess, ProcessObjectAttributes, ThreadObjectAttributes, ProcessFlags, ThreadFlags, ProcessParameters, CreateInfo, pAttributeList);
#endif
}
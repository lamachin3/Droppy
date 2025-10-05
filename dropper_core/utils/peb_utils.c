#include "peb_utils.h"


PVOID GetSectionAddress(HMODULE hMod, LPCSTR lpSectionName, DWORD *pdwSectionSize)
{
    if (hMod == NULL) return NULL;

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hMod;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)hMod + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) return NULL;

    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
    WORD wSections = pNtHeaders->FileHeader.NumberOfSections;

    for (WORD i = 0; i < wSections; i++, pSectionHeader++)
    {
        if (strncmp((CHAR*)pSectionHeader->Name, lpSectionName, IMAGE_SIZEOF_SHORT_NAME) == 0)
        {
            if (pdwSectionSize)
                *pdwSectionSize = pSectionHeader->Misc.VirtualSize;

            return (PVOID)((PBYTE)hMod + pSectionHeader->VirtualAddress);
        }
    }

    return NULL;
}
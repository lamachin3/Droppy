#ifndef PEB_UTILS_H
#define PEB_UTILS_H

#include "../common.h"

PVOID GetSectionAddress(HMODULE hMod, LPCSTR lpSectionName, DWORD *pdwSectionSize);

#endif
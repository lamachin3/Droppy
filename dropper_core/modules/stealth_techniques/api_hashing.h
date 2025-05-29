#ifndef API_HASHING_H
#define API_HASHING_H

#include "../../common.h"

FARPROC GetProcAddressH(HMODULE hModule, DWORD dwApiNameHash);
HMODULE GetModuleHandleH(DWORD dwModuleNameHash);

#endif

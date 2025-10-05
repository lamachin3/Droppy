#ifndef ASM_UTILS_H
#define ASM_UTILS_H

#include "../common.h"

LPBYTE find_asm_pattern(const BYTE *pPattern, SIZE_T patternSize, LPBYTE startAddr, SIZE_T before, SIZE_T after);
PBYTE findRetInstruction(PVOID function_start);

#endif // ASM_UTILS_H

#include "asm_utils.h"

LPBYTE find_asm_pattern(const BYTE *pPattern, SIZE_T patternSize, LPBYTE startAddr, SIZE_T before, SIZE_T after) {
    if (!pPattern || patternSize == 0 || !startAddr) {
        return NULL;
    }

    LPBYTE searchStart = startAddr - before;
    LPBYTE searchEnd   = startAddr + after;

    for (LPBYTE p = searchStart; p < (searchEnd - patternSize); p++) {
        if (*p == pPattern[0]) {
            if (memcmp(p, pPattern, patternSize) == 0) {
                return p;
            }
        }
    }

    return NULL;
}

PBYTE findRetInstruction(PVOID function_start) {
	unsigned char* ptr = (unsigned char*)function_start;
	for (int i = 0; i < 0x400; i++) {
		if (ptr[i] == 0xC3) {
			return &ptr[i];
		}
	}
	return NULL;
}
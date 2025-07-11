#include "debug.h"
#include <stdarg.h>


VOID DebugPrint(PCSTR format, ...)
{
#ifdef DEBUG
    va_list args;
    va_start(args, format);
    #ifdef NO_CRT_LIB
    // PRINTA expects variadic arguments, not va_list
    PRINTA(format, args);
    #else
    vprintf(format, args);
    #endif
    va_end(args);
#endif
}

VOID WDebugPrint(PCWSTR format, ...) {
#ifdef DEBUG
    va_list args;
    va_start(args, format);
    #ifdef NO_CRT_LIB
    // PRINTW expects variadic arguments, not va_list
    PRINTW(format, args);
    #else
    vwprintf(format, args);
    #endif
    va_end(args);
#endif
}

void PrintMemoryBytes(HANDLE hProcess, PVOID pAddress, SIZE_T byteCount) {
    BYTE buffer[20]; // Buffer to hold the first 20 bytes
    SIZE_T bytesRead = 0;

    if (byteCount > sizeof(buffer)) {
        DebugPrint("[!] Requested byte count exceeds buffer size.\n");
        return;
    }

    if (ReadProcessMemory(hProcess, pAddress, buffer, byteCount, &bytesRead)) {
        DebugPrint("\n<========     MEMORY OUTPUT     ========>\n");
        DebugPrint("[i] Memory at 0x%p (First %llu bytes):\n", pAddress, byteCount);
        for (SIZE_T i = 0; i < bytesRead; i++) {
            DebugPrint("%02X ", buffer[i]);
        }
    }
    else {
        DebugPrint("[!] Failed to read process memory at 0x%p. Error: %lu\n", pAddress, GetLastError());
    }
    DebugPrint("\n<===================================================>\n\n");
}
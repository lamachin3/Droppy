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

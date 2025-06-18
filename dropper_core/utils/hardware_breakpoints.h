#ifndef HARDARE_BREAKPOINTS_H
#define HARDARE_BREAKPOINTS_H

#include "../common.h"

#define CONTINUE_EXECUTION(CTX)(CTX->EFlags = CTX->EFlags | (1 << 16))

BOOL InitHardwareBreakpointHooking();
BOOL CleapUpHardwareBreakpointHooking();

BOOL InstallHardwareBreakingPntHook(IN PUINT_VAR_T Address, IN DRX Drx, IN PVOID CallbackRoutine, IN DWORD ThreadId);
BOOL RemoveHardwareBreakingPntHook(IN PUINT_VAR_T Address, IN DWORD ThreadId);

BOOL InstallHooksOnNewThreads(IN DRX Drx);
BOOL RemoveHooksOnNewThreads();

VOID BLOCK_REAL(IN PCONTEXT pThreadCtx);

ULONG_PTR GetFunctionArgument(IN PCONTEXT pThreadCtx, IN DWORD dwParmIndex);
VOID SetFunctionArgument(IN PCONTEXT pThreadCtx, IN ULONG_PTR uValue, IN DWORD dwParmIndex);

#endif // HARDARE_BREAKPOINTS_H
#ifndef ETW_BYPASS_H
#define ETW_BYPASS_H

#include "../../common.h"

#define x64_RET_INSTRUCTION_OPCODE			0xC3		// 'ret'	- instruction opcode
#define x64_MOV_INSTRUCTION_OPCODE			0xB8		// 'mov'	- instruction opcode
#define x64_JMP_INSTRUCTION_OPCODE			0xE9		// 'jmp'	- instruction opcode
#define	x64_SYSCALL_STUB_SIZE				0x20		// size of a syscall stub is 32
#define x64_CALL_INSTRUCTION_OPCODE			0xE8		// 'call'	- instruction opcode
#define x64_INT3_INSTRUCTION_OPCODE			0xCC		// 'int3'	- instruction opcode
#define NOP_INSTRUCTION_OPCODE				0x90		// 'nop'	- instruction opcode
#define PATCH_SIZE							0x05

// Called in the detour functions to continue execution
#define CONTINUE_EXECUTION(CTX)(CTX->EFlags = CTX->EFlags | (1 << 16))

// Called in the detour function to return a value
#define SET_RETURN_VALUE(CTX, VALUE) (CTX->Rax = (ULONG_PTR)VALUE)
// Called in the detour function to block the execution of the original function
VOID BLOCK_REAL(IN PCONTEXT pThreadCtx);

PVOID fetchEtwpEventWriteFullAddr(HANDLE hProcess);
BOOL applyEtwBypass(HANDLE hProcess);

/**
 * @brief Modify the SSN of ETW related syscalls to return an error. 
 * 
 * Modify the mov eax, <SSN> instruction of ETW-related syscalls to replace the legitimate System Service Number (SSN) with a fake or invalid SSN.
 * 
 * @param hProcess Handle to the target process.
 * @param syscallName Name of the target syscall.
 * 
 * @return TRUE if the syscall was properly altered, FALSE otherwise.
 * 
 * @name Syscall ETW Patch
 * @section etw_bypass
 * @flags SYSCALL_BASED_ETW_PATCH
*/
BOOL SyscallPatchEtw(HANDLE hProcess, LPSTR syscallName);

/**
 * @brief Modify ETW functions to return directly instead of running their logic.
 *
 * Modifies the ETW functions by patching them with:
 * xor eax, eax to set a valid return value
 * jmp <ret_address> to skip the function logic and return immediately.
 *
 * @param hProcess Handle to the target process.
 * @param functionName Name of the ETW function to patch ("EtwEventWrite", "EtwEventWriteEx", "EtwEventWriteFull", "EtwpEventWriteFull").
 *
 * @return TRUE if the ETW patch was successfully applied, FALSE otherwise.
 *
 * @name Jmp Ret Based ETW Patch
 * @section etw_bypass
 * @flags JMP_RET_BASED_ETW_PATCH
*/
BOOL JmpRetBasedEtwPatch(HANDLE hProcess, LPSTR functionName);

/**
 * @brief Modify ETW functions to not execute EtwpEventWriteFull.
 *
 * This function patches ETW functions by replacing the call instruction to EtwpEventWriteFull with a NOP sled.
 *
 * @param hProcess Handle to the target process.
 * @param functionName Name of the ETW function to patch ("EtwEventWrite", "EtwEventWriteEx", "EtwEventWriteFull", "EtwpEventWriteFull").
 *
 * @return TRUE if the ETW patch was successfully applied, FALSE otherwise.
 *
 * @name Call Based ETW Patch
 * @section etw_bypass
 * @flags CALL_BASED_ETW_PATCH
*/
BOOL CallBasedEtwPatch(HANDLE hProcess, LPSTR functionName);

/**
 * @brief Hook ETW functions using hardware breakpoints.
 *
 * This function installs hardware breakpoints on the specified ETW function to intercept calls and redirect them to a custom callback.
 *
 * @param hProcess Handle to the target process.
 * @param functionName Name of the ETW function to hook ("EtwEventWrite", "EtwEventWriteEx", "EtwEventWriteFull", "EtwpEventWriteFull").
 *
 * @return TRUE if the hooking was successful, FALSE otherwise.
 *
 * @name Hardware Breakpoint Hooking
 * @section etw_bypass
 * @flags HBP_ETW_HOOKING
*/
BOOL HbpEtwHooking(HANDLE hProcess, LPSTR functionName);

#endif // ETW_BYPASS_H
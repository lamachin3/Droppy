#ifndef SYSCALLS_H
#define SYSCALLS_H

#include "../common.h"
#include "hw_indirect_syscalls.h"

BOOL InitializeSyscalls();

/**
 * @brief Runs the Windows API through indirect Syscalls using HWSyscalls technique.
 *
 * @param functionName String to the function name.
 * 
 * @return TRUE if the syscall has been found, FALSE otherwise.
 * 
 * @name HW Indirect Syscall
 * @flags HW_INDIRECT_SYSCALL
 */
UINT64 PrepareSyscall(char* functionName);

#endif
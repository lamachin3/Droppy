#ifndef SYSCALLS_H
#define SYSCALLS_H

#include "../common.h"

/**
 * @brief Perform Direct Syscals using the SysWhispers3 technique.
 * 
 * @name SysWhispers3 Direct Syscalls
 * @section syscalls
 * @flags SW3_SYSCALLS
 * @tags direct_syscall
*/
#include "direct/SysWhispers3/sw3_syscalls.h"
/**
 * @brief Perform Indirect Syscals using the HWSyscalls technique.
 * 
 * @name HWSyscalls Indirect Syscalls
 * @section syscalls
 * @flags HW_SYSCALLS
 * @tags indirect_syscall
*/
#include "indirect/HWSyscalls/hw_syscalls.h"

BOOL InitializeSyscalls();

#endif
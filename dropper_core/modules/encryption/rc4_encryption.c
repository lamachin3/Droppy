#include "encryption.h"


// defining how does the function look - more on this structure in the api hashing part
typedef NTSTATUS(NTAPI* fnSystemFunction032)(
        struct USTRING* Img,
        struct USTRING* Key
);

BOOL Rc4Decrypt(IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize) {

        // the return of SystemFunction032
        NTSTATUS        STATUS = NULL;

        // making 2 USTRING variables, 1 passed as key and one passed as the block of data to encrypt/decrypt
        USTRING         Key = { .Buffer = pRc4Key,              .Length = dwRc4KeySize,         .MaximumLength = dwRc4KeySize },
                        Img = { .Buffer = pPayloadData,         .Length = sPayloadSize,         .MaximumLength = sPayloadSize };


        // since SystemFunction032 is exported from Advapi32.dll, we load it Advapi32 into the prcess,
        // and using its return as the hModule parameter in GetProcAddress
        fnSystemFunction032 SystemFunction032 = (fnSystemFunction032)GetProcAddress(LoadLibraryA("Advapi32"), "SystemFunction032");

        // if SystemFunction032 calls failed it will return non zero value
        if ((STATUS = SystemFunction032(&Img, &Key)) != 0x0) {
                DebugPrint("[!] SystemFunction032 FAILED With Error : 0x%0.8X\n", STATUS);
                return FALSE;
        }

        return TRUE;
}

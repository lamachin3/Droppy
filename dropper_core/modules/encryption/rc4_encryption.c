#include "encryption.h"


// defining how does the function look - more on this structure in the api hashing part
typedef NTSTATUS(NTAPI* fnSystemFunction032)(
        struct USTRING* Img,
        struct USTRING* Key
);

BOOL Rc4Decrypt(IN PBYTE pPayloadData, IN SIZE_T sPayloadSize, IN PBYTE pRc4Key, IN SIZE_T dwRc4KeySize, OUT PBYTE *pPlainTextData, OUT SIZE_T *sPlainTextSize) {
        // The return of SystemFunction032
        NTSTATUS STATUS = NULL;
    
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
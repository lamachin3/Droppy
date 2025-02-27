#ifndef INJECTION_H
#define INJECTION_H

#include "../../common.h"

BOOL inject_payload(LPVOID Payload, SIZE_T PayloadSize);

/**
 * @brief Injects a payload into a specified process and thread using APC (Asynchronous Procedure Call).
 *
 * This function injects a specified payload into a target process and thread using the APC mechanism.
 * APCs are a way to asynchronously execute code in the context of a target thread.
 *
 * @param hProcess Handle to the target process.
 * @param hThread Handle to the target thread.
 * @param pPayload Pointer to the payload to be injected.
 * @param sPayloadSize Size of the payload in bytes.
 *
 * @return TRUE if the payload was successfully injected, FALSE otherwise.
 * 
 * @name APC Injection
 * @section injection_technique
 */
BOOL InjectPayloadViaAPC(HANDLE hProcess, HANDLE hThread, PVOID pPayload, SIZE_T sPayloadSize);

#endif
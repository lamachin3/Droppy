#ifndef INJECTION_H
#define INJECTION_H

#include "../../common.h"

BOOL inject_payload(LPVOID Payload, SIZE_T PayloadSize, ...);


/**
 * @brief Injects a payload into a specified remote process.
 * 
 * This function injects a specified payload into a target process. The target process is identified by its name.
 * The function allocates memory in the target process, writes the payload into that memory, and then creates a remote thread to execute the payload.
 * 
 * @param hProcess Handle to the target process.
 * @param szProcessName Name of the target process.
 * @param Payload Pointer to the payload to be injected.
 * @param PayloadSize Size of the payload in bytes.
 * 
 * @return TRUE if the payload was successfully injected, FALSE otherwise.
 * 
 * @name Remote Process Injection
 * @section injection_technique
*/
BOOL RemoteProcessInjection(HANDLE hProcess, LPWSTR szProcessName, PBYTE pShellcode, SIZE_T sPayloadSize);


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
BOOL ApcInjection(HANDLE hProcess, HANDLE hThread, PBYTE pPayload, SIZE_T sPayloadSize);


/**
 * @brief Injects a payload into a specified process using the Early Bird technique.
 * 
 * This function injects a specified payload into a target process using the Early Bird technique.
 * The Early Bird technique involves injecting the payload into a suspended process before it starts executing.
 * This ensures that the payload is executed as soon as the process starts.
 * 
 * @param hProcess Handle to the target process.
 * @param hThread Handle to the target thread.
 * @param szProcessName Name of the target process.
 * @param pPayload Pointer to the payload to be injected.
 * @param sPayloadSize Size of the payload in bytes.
 * 
 * @return TRUE if the payload was successfully injected, FALSE otherwise.
 * 
 * @name Early Bird Injection (Remote Process)
 * @section injection_technique
*/
BOOL EarlyBirdApcInjection(HANDLE hProcess, HANDLE hThread, LPWSTR szProcessName, PBYTE pPayload, SIZE_T sPayloadSize);


#endif
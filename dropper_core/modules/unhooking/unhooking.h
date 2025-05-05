#ifndef UNHOOKING_H
#define UNHOOKING_H

#include "../../common.h"

BOOL ReplaceNtdllTxtSection(IN PVOID pUnhookedNtdll);
PVOID FetchLocalNtdllBaseAddress();

/**
 * @brief Unhooks the NTDLL text section for a given process by creating a suspended process and restoring the NTDLL text section from a clean source.
 * 
 * This function is designed to bypass user-mode hooks in NTDLL, often used by 
 * malware or debugging tools, by creating a suspended copy of the target process 
 * and restoring the NTDLL text section from a clean source.
 * 
 * @param lpProcessName The name of the target process (e.g., "notepad.exe") for 
 *                      which the NTDLL text section should be unhooked.
 * 
 * @return Returns TRUE if the unhooking process was successful, otherwise FALSE.
 *         The function also sets the appropriate error code that can be retrieved
 *         with GetLastError().
 * 
 * @name Suspended Process Unhooking
 * @section unhooking
*/
BOOL UnhookNtdllTextSectionViaSuspended(IN PWSTR lpProcessName);

/**
 * @brief Unhooks the NTDLL text section for a given process by using the KnownDlls directory as a reference for a clean NTDLL.
 * 
 * This function restores the NTDLL text section in the memory space of the target 
 * process by leveraging the clean version of NTDLL found in the KnownDlls directory.
 * It is useful for evading hooks set in user-mode for process manipulation or 
 * monitoring.
 * 
 * @param lpProcessName The name of the target process (e.g., "notepad.exe") for 
 *                      which the NTDLL text section should be unhooked.
 * 
 * @return Returns TRUE if the unhooking process was successful, otherwise FALSE.
 *         The function also sets the appropriate error code that can be retrieved
 *         with GetLastError().
 * 
 * @name Known Dlls Unhooking
 * @section unhooking
*/
BOOL UnhookNtdllTextSectionViaKnownDlls();


#endif
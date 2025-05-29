#include "crypto.h"


/**
 * XorByInputKey - XORs each byte of the shellcode with the corresponding byte of the key.
 *
 * @pShellcode: Pointer to the shellcode to be XORed.
 * @sShellcodeSize: Size of the shellcode in bytes.
 * @bKey: Pointer to the key to be used for XORing.
 * @sKeySize: Size of the key in bytes.
 *
 * This function XORs each byte of the shellcode with the corresponding byte of the key.
 * If the key is shorter than the shellcode, the key is repeated.
 */
BOOL XorDecrypt(IN PBYTE pShellcode, IN SIZE_T sShellcodeSize, IN PBYTE bKey, IN SIZE_T sKeySize) {
	for (size_t i = 0, j = 0; i < sShellcodeSize; i++, j++) {
		if (j >= sKeySize){
			j = 0;
		}
		pShellcode[i] = pShellcode[i] ^ bKey[j];
	}
	return TRUE;
}
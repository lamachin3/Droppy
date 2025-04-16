#include "encryption.h"

#define BCRYPT_CHACHA20_POLY1305_ALGORITHM L"CHACHA20_POLY1305"


BOOL ChaCha20Decrypt(IN PVOID pCipherTextData, IN DWORD sCipherTextSize, IN PBYTE pKey, IN PBYTE pNonce, OUT PBYTE *pPlainTextData, OUT SIZE_T *sPlainTextSize) {
    BCRYPT_KEY_HANDLE hKey = NULL;
    BCRYPT_ALG_HANDLE hAlg = NULL;
    NTSTATUS status;
    DWORD decryptedSize = 0;
    PBYTE decrypted = NULL;

    // Open an algorithm handle
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_CHACHA20_POLY1305_ALGORITHM, NULL, 0);
    if (FAILED(status)) {
        DebugPrint("Error opening algorithm provider: 0x%x\n", status);
        return FALSE;
    }

    // Generate the key
    status = BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, pKey, sizeof(pKey), 0);
    if (FAILED(status)) {
        DebugPrint("Error generating symmetric key: 0x%x\n", status);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return FALSE;
    }

    // Allocate memory for the decrypted data
    decrypted = (PBYTE)malloc(sCipherTextSize);
    if (!decrypted) {
        DebugPrint("Memory allocation failed\n");
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return FALSE;
    }

    // Decrypt the data
    status = BCryptDecrypt(hKey, (PUCHAR)pCipherTextData, sCipherTextSize, NULL, pNonce, sizeof(pNonce), decrypted, sCipherTextSize, &decryptedSize, BCRYPT_BLOCK_PADDING);
    if (FAILED(status)) {
        DebugPrint("Error decrypting data: 0x%x\n", status);
        free(decrypted);
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return FALSE;
    }

    // Set the output parameters
    *pPlainTextData = decrypted;
    *sPlainTextSize = decryptedSize;

    // Clean up
    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    return TRUE;
}

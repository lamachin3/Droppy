#include "encryption.h"


BOOL RsaDecrypt(
    IN PVOID pCipherTextData,
    IN DWORD sCipherTextSize,
    IN PBYTE pPrivateKey,
    IN DWORD sPrivateKeySize,
    OUT PVOID *pPlainTextData,
    OUT DWORD *sPlainTextSize
) {
    BCRYPT_KEY_HANDLE hKey = NULL;
    BCRYPT_ALG_HANDLE hAlg = NULL;
    NTSTATUS status;
    DWORD decryptedSize = 0;
    PBYTE decrypted = NULL;

    // Open an algorithm handle
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RSA_ALGORITHM, NULL, 0);
    if (FAILED(status)) {
        DebugPrint("Error opening algorithm provider: 0x%x\n", status);
        return FALSE;
    }

    // Import the private key
    status = BCryptImportKeyPair(hAlg, NULL, BCRYPT_RSAPRIVATE_BLOB, &hKey, pPrivateKey, sPrivateKeySize, 0);
    if (FAILED(status)) {
        DebugPrint("Error importing key pair: 0x%x\n", status);
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
    status = BCryptDecrypt(hKey, (PUCHAR)pCipherTextData, sCipherTextSize, NULL, NULL, 0, decrypted, sCipherTextSize, &decryptedSize, BCRYPT_PAD_PKCS1);
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

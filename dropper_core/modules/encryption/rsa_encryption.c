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



// Define offsets for RSA key parsing based on the expected key format
#define OFFSET_MODULUS 32
#define OFFSET_EXPONENT 8

// Function to perform modular exponentiation: result = base^exp % mod
void ModExp(BYTE* result, BYTE* base, BYTE* exp, BYTE* mod, size_t modSize) {
    BYTE temp[512] = { 0 };  // Temporary buffer for calculations
    BYTE one[512] = { 0 };
    one[modSize - 1] = 1;  // Represent "1" in big-endian format

    // Copy base into temp (temp = base mod n)
    memcpy(temp, base, modSize);

    // Set result to 1
    memcpy(result, one, modSize);

    // Process each bit of the exponent (Big Integer Modular Exponentiation)
    for (int i = modSize * 8 - 1; i >= 0; i--) {
        // Square result (result = result^2 mod mod)
        MultiplyMod(result, result, result, mod, modSize);

        // If the current bit of exp is 1, multiply by base
        if ((exp[i / 8] >> (i % 8)) & 1) {
            MultiplyMod(result, result, temp, mod, modSize);
        }
    }
}

// Function to perform modular multiplication: result = (a * b) % mod
void MultiplyMod(BYTE* result, BYTE* a, BYTE* b, BYTE* mod, size_t modSize) {
    BYTE temp[1024] = { 0 };
    memset(result, 0, modSize);

    for (int i = 0; i < modSize * 8; i++) {
        if ((b[i / 8] >> (i % 8)) & 1) {
            AddMod(temp, result, a, mod, modSize);
            memcpy(result, temp, modSize);
        }
        // Double a (a = (a * 2) % mod)
        AddMod(temp, a, a, mod, modSize);
        memcpy(a, temp, modSize);
    }
}

// Function to perform modular addition: result = (a + b) % mod
void AddMod(BYTE* result, BYTE* a, BYTE* b, BYTE* mod, size_t modSize) {
    BYTE temp[512] = { 0 };

    for (int i = modSize - 1, carry = 0; i >= 0; i--) {
        temp[i] = a[i] + b[i] + carry;
        carry = (temp[i] < a[i]);
    }

    // If temp >= mod, subtract mod
    if (memcmp(temp, mod, modSize) >= 0) {
        for (int i = modSize - 1, borrow = 0; i >= 0; i--) {
            temp[i] -= mod[i] + borrow;
            borrow = (temp[i] > (255 - mod[i]));
        }
    }
    memcpy(result, temp, modSize);
}

BOOL RsaDecryptStandAlone(
    IN PVOID pCipherTextData,
    IN DWORD sCipherTextSize,
    IN PBYTE pPrivateKey,
    IN DWORD sPrivateKeySize,
    OUT PVOID* pPlainTextData,
    OUT DWORD* sPlainTextSize
) {
    NTSTATUS status;
    SIZE_T regionSize = sCipherTextSize;
    PBYTE decrypted = NULL;

    // Allocate memory for the decrypted data using syscalls
    NtAllocateVirtualMemory_t pNtAllocateVirtualMemory = (NtAllocateVirtualMemory_t)PrepareSyscallHash(NtAllocateVirtualMemory_JOAA);

    status = pNtAllocateVirtualMemory(GetCurrentProcess(), (PVOID*)&decrypted, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (status != 0) {
        DebugPrint("[-] NtAllocateVirtualMemory failed: 0x%X\n", status);
        return FALSE;
    }

    // Parse the RSA private key blob (Extract modulus and exponent)
    BYTE* modulus = pPrivateKey + OFFSET_MODULUS;  // OFFSET_MODULUS depends on key format
    BYTE* exponent = pPrivateKey + OFFSET_EXPONENT;

    // Perform modular exponentiation (RSA decryption)
    ModExp(decrypted, (BYTE*)pCipherTextData, exponent, modulus, sCipherTextSize);

    // Set output parameters
    *pPlainTextData = decrypted;
    *sPlainTextSize = sCipherTextSize;

    return TRUE;
}

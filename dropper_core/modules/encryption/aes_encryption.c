#include "encryption.h"

#pragma comment(lib, "Bcrypt.lib")


#define KEYSIZE         32
#define IVSIZE          16

typedef struct _AES {
        PBYTE   pPlainText;             // base address of the plain text data
        DWORD   dwPlainSize;            // size of the plain text data

        PBYTE   pCipherText;            // base address of the encrypted data
        DWORD   dwCipherSize;           // size of it (this can change from dwPlainSize in case there was padding)

        PBYTE   pKey;                   // the 32 byte key
        PBYTE   pIv;                    // the 16 byte iv
}AES, * PAES;

// the real decryption implemantation
BOOL InstallAesDecryption(PAES pAes) {

        BOOL                            bSTATE = TRUE;

        BCRYPT_ALG_HANDLE               hAlgorithm = NULL;
        BCRYPT_KEY_HANDLE               hKeyHandle = NULL;

        ULONG                           cbResult = 0;
        DWORD                           dwBlockSize = 0;

        DWORD                           cbKeyObject = 0;
        PBYTE                           pbKeyObject = 0;

        PBYTE                           pbPlainText = NULL;
        DWORD                           cbPlainText = 0;

        NTSTATUS                        STATUS          = STATUS_SUCCESS;

        // intializing "hAlgorithm" as AES algorithm Handle
        STATUS = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, NULL, 0);
        if (!NT_SUCCESS(STATUS)) {
                DebugPrint("[!] BCryptOpenAlgorithmProvider Failed With Error: 0x%0.8X \n", STATUS);
                bSTATE = FALSE; goto _EndOfFunc;
        }
        // getting the size of the key object variable *pbKeyObject* this is used for BCryptGenerateSymmetricKey function later
        STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(DWORD), &cbResult, 0);
        if (!NT_SUCCESS(STATUS)) {
                DebugPrint("[!] BCryptGetProperty[1] Failed With Error: 0x%0.8X \n", STATUS);
                bSTATE = FALSE; goto _EndOfFunc;
        }
        // getting the size of the block used in the encryption, since this is aes it should be 16 (this is what AES does)
        STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_BLOCK_LENGTH, (PBYTE)&dwBlockSize, sizeof(DWORD), &cbResult, 0);
        if (!NT_SUCCESS(STATUS)) {
                DebugPrint("[!] BCryptGetProperty[2] Failed With Error: 0x%0.8X \n", STATUS);
                bSTATE = FALSE; goto _EndOfFunc;
        }
        // checking if block size is 16
        if (dwBlockSize != 16) {
                bSTATE = FALSE; goto _EndOfFunc;
        }
        // allocating memory for the key object
        pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
        if (pbKeyObject == NULL) {
                bSTATE = FALSE; goto _EndOfFunc;
        }
        // setting Block Cipher Mode to CBC (32 byte key and 16 byte Iv)
        STATUS = BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
        if (!NT_SUCCESS(STATUS)) {
                DebugPrint("[!] BCryptSetProperty Failed With Error: 0x%0.8X \n", STATUS);
                bSTATE = FALSE; goto _EndOfFunc;
        }
        // generating the key object from the aes key "pAes->pKey", the output will be saved in "pbKeyObject" of size "cbKeyObject"
        STATUS = BCryptGenerateSymmetricKey(hAlgorithm, &hKeyHandle, pbKeyObject, cbKeyObject, (PBYTE)pAes->pKey, KEYSIZE, 0);
        if (!NT_SUCCESS(STATUS)) {
                DebugPrint("[!] BCryptGenerateSymmetricKey Failed With Error: 0x%0.8X \n", STATUS);
                bSTATE = FALSE; goto _EndOfFunc;
        }
        // running BCryptDecrypt first time with NULL output parameters, thats to deduce the size of the output buffer, (the size will be saved in cbPlainText)
        STATUS = BCryptDecrypt(hKeyHandle, (PUCHAR)pAes->pCipherText, (ULONG)pAes->dwCipherSize, NULL, pAes->pIv, IVSIZE, NULL, 0, &cbPlainText, BCRYPT_BLOCK_PADDING);
        if (!NT_SUCCESS(STATUS)) {
                DebugPrint("[!] BCryptDecrypt[1] Failed With Error: 0x%0.8X \n", STATUS);
                bSTATE = FALSE; goto _EndOfFunc;
        }
        // allocating enough memory (of size cbPlainText)
        pbPlainText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbPlainText);
        if (pbPlainText == NULL) {
                bSTATE = FALSE; goto _EndOfFunc;
        }
        // running BCryptDecrypt second time with "pbPlainText" as output buffer
        STATUS = BCryptDecrypt(hKeyHandle, (PUCHAR)pAes->pCipherText, (ULONG)pAes->dwCipherSize, NULL, pAes->pIv, IVSIZE, pbPlainText, cbPlainText, &cbResult, BCRYPT_BLOCK_PADDING);
        if (!NT_SUCCESS(STATUS)) {
                DebugPrint("[!] BCryptDecrypt[2] Failed With Error: 0x%0.8X \n", STATUS);
                bSTATE = FALSE; goto _EndOfFunc;
        }
        // cleaning up
_EndOfFunc:
        if (hKeyHandle) {
                BCryptDestroyKey(hKeyHandle);
        }
        if (hAlgorithm) {
                BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        }
        if (pbKeyObject) {
                HeapFree(GetProcessHeap(), 0, pbKeyObject);
        }
        if (pbPlainText != NULL && bSTATE) {
                // if everything went well, we save pbPlainText and cbPlainText
                pAes->pPlainText = pbPlainText;
                pAes->dwPlainSize = cbPlainText;
        }
        return bSTATE;
}


// wrapper function for InstallAesDecryption that make things easier
BOOL SimpleAesDecryption(IN PVOID pCipherTextData, IN DWORD sCipherTextSize, IN PBYTE pKey, IN PBYTE pIv, OUT PBYTE *pPlainTextData, OUT SIZE_T *sPlainTextSize) {
        if (pCipherTextData == NULL || sCipherTextSize == NULL || pKey == NULL || pIv == NULL)
                return FALSE;

        AES Aes = {
                .pKey = pKey,
                .pIv = pIv,
                .pCipherText = pCipherTextData,
                .dwCipherSize = sCipherTextSize
        };

        if (!InstallAesDecryption(&Aes)) {
                return FALSE;
        }

        *pPlainTextData = Aes.pPlainText;
        *sPlainTextSize = Aes.dwPlainSize;

        return TRUE;
}

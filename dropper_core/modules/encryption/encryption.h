#ifndef DECRYPT_H
#define DECRYPT_H

#include "../../common.h"


BOOL decrypt(IN PBYTE pShellcode, IN SIZE_T sShellcodeSize, IN PBYTE pKey, IN SIZE_T sKeySize, IN PBYTE pIv, OUT PBYTE *pPlainTextData, OUT SIZE_T *sPlainTextSize);

/**
 * @brief Decrypts the given ciphertext using AES decryption.
 *
 * @param pCipherTextData Pointer to the ciphertext data.
 * @param sCipherTextSize Size of the ciphertext data.
 * @param pKey Pointer to the AES decryption key.
 * @param pIv Pointer to the initialization vector.
 * @param pPlainTextData Pointer to the decrypted plaintext data.
 * @param sPlainTextSize Pointer to the size of the decrypted plaintext data.
 * 
 * @return TRUE if decryption is successful, FALSE otherwise.
 * 
 * @name AES Encryption
 * @flags ENCRYPTED_PAYLOAD,AES_ENCRYPTION
 */
BOOL SimpleAesDecryption(IN PVOID pCipherTextData, IN DWORD sCipherTextSize, IN PBYTE pKey, IN PBYTE pIv, OUT PBYTE *pPlainTextData, OUT SIZE_T *sPlainTextSize);

/**
 * @_brief Decrypts the given ciphertext using ChaCha20 decryption.
 *
 * @param pCipherTextData Pointer to the ciphertext data.
 * @param sCipherTextSize Size of the ciphertext data.
 * @param pKey Pointer to the ChaCha20 decryption key.
 * @param pNonce Pointer to the nonce.
 * @param pPlainTextData Pointer to the decrypted plaintext data.
 * @param sPlainTextSize Pointer to the size of the decrypted plaintext data.
 * 
 * @return TRUE if decryption is successful, FALSE otherwise.
 * 
 * @_name ChaCha20 Encryption
 */
BOOL ChaCha20Decrypt(IN PVOID pCipherTextData, IN DWORD sCipherTextSize, IN PBYTE pKey, IN PBYTE pNonce, OUT PBYTE *pPlainTextData, OUT SIZE_T *sPlainTextSize);

/**
 * @_brief Decrypts the given ciphertext using DES decryption.
 *
 * @param pCipherTextData Pointer to the ciphertext data.
 * @param sCipherTextSize Size of the ciphertext data.
 * @param pKey Pointer to the DES decryption key.
 * @param pIv Pointer to the initialization vector.
 * @param pPlainTextData Pointer to the decrypted plaintext data.
 * @param sPlainTextSize Pointer to the size of the decrypted plaintext data.
 * 
 * @return TRUE if decryption is successful, FALSE otherwise.
 * 
 * @_name DES Encryption
 */
BOOL DesDecrypt(IN PVOID pCipherTextData, IN DWORD sCipherTextSize, IN PBYTE pKey, IN PBYTE pIv, OUT PBYTE *pPlainTextData, OUT SIZE_T *sPlainTextSize);

/**
 * @brief Decrypts the given payload using RC4 decryption.
 *
 * @param pPayloadData Pointer to the payload data.
 * @param sPayloadSize Size of the payload data.
 * @param pRc4Key Pointer to the RC4 decryption key.
 * @param dwRc4KeySize Size of the RC4 decryption key.
 * 
 * @return TRUE if decryption is successful, FALSE otherwise.
 * 
 * @name RC4 Encryption
 * @flags ENCRYPTED_PAYLOAD,RC4_ENCRYPTION
 */
BOOL Rc4Decrypt(IN PBYTE pPayloadData, IN SIZE_T sPayloadSize, IN PBYTE pRc4Key, IN SIZE_T dwRc4KeySize, OUT PBYTE *pPlainTextData, OUT SIZE_T *sPlainTextSize);

/**
 * @_brief Decrypts the given ciphertext using RSA decryption.
 *
 * @param pCipherTextData Pointer to the ciphertext data.
 * @param sCipherTextSize Size of the ciphertext data.
 * @param pPrivateKey Pointer to the RSA private key.
 * @param sPrivateKeySize Size of the RSA private key.
 * @param pPlainTextData Pointer to the decrypted plaintext data.
 * @param sPlainTextSize Pointer to the size of the decrypted plaintext data.
 * 
 * @return TRUE if decryption is successful, FALSE otherwise.
 * 
 * @_name RSA Encryption
 */
BOOL RsaDecrypt(IN PVOID pCipherTextData, IN DWORD sCipherTextSize, IN PBYTE pPrivateKey, IN DWORD sPrivateKeySize, OUT PBYTE *pPlainTextData, OUT SIZE_T *sPlainTextSize);
void MultiplyMod(BYTE* result, BYTE* a, BYTE* b, BYTE* mod, size_t modSize);
void AddMod(BYTE* result, BYTE* a, BYTE* b, BYTE* mod, size_t modSize);
void ModExp(BYTE* result, BYTE* base, BYTE* exp, BYTE* mod, size_t modSize);

/**
 * @brief Decrypts the given shellcode using XOR decryption.
 *
 * @param pShellcode Pointer to the shellcode to be decrypted.
 * @param sShellcodeSize Size of the shellcode.
 * @param bKey Pointer to the XOR decryption key.
 * @param sKeySize Size of the XOR decryption key.
 * 
 * @return TRUE if decryption is successful, FALSE otherwise.
 * 
 * @name XOR Encryption
 * @flags ENCRYPTED_PAYLOAD,XOR_ENCRYPTION
 */
BOOL XorDecrypt(IN PBYTE pShellcode, IN SIZE_T sShellcodeSize, IN PBYTE bKey, IN SIZE_T sKeySize);

#endif
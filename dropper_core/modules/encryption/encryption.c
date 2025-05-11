#include "encryption.h"


BOOL decrypt(IN PBYTE pShellcode, IN SIZE_T sShellcodeSize, IN PBYTE pKey, IN SIZE_T sKeySize, IN PBYTE pIv, OUT PBYTE *pPlainTextData, OUT SIZE_T *sPlainTextSize) {
#if defined(AES_ENCRYPTION)
    return SimpleAesDecryption(pShellcode, sShellcodeSize, pKey, pIv, pPlainTextData, sPlainTextSize);
#elif defined(CHACHA20_ENCRYPTION)
    return ChaCha20Decrypt(pShellcode, sShellcodeSize, pKey, pNonce, pPlainTextData, sPlainTextSize);
#elif defined(DES_ENCRYPTION)
    return DesDecrypt(pShellcode, sShellcodeSize, pKey, pIv, pPlainTextData, sPlainTextSize);
#elif defined(RC4_ENCRYPTION)
    return Rc4Decrypt(pShellcode, sShellcodeSize, pKey, sKeySize, pPlainTextData, sPlainTextSize);
#elif defined(RSA_ENCRYPTION)
    return RsaDecrypt(pShellcode, sShellcodeSize, pPrivateKey, sPrivateKeySize, pPlainTextData, sPlainTextSize);
#elif defined(XOR_ENCRYPTION)
    NTSTATUS status = 0;
    status = XorDecrypt(pShellcode, sShellcodeSize, pKey, sKeySize);
    *pPlainTextData = pShellcode;
    *sPlainTextSize = sShellcodeSize;
    return status;
#endif

    return TRUE;
}

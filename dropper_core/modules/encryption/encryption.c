#include "encryption.h"


BOOL decrypt(IN PBYTE pShellcode, IN SIZE_T sShellcodeSize, IN PBYTE bKey, IN SIZE_T sKeySize) {
#if defined(AES_ENCRYPTION)
    return SimpleAesDecryption(pCipherTextData, sCipherTextSize, pKey, pIv, &pPlainTextData, &sPlainTextSize);
#elif defined(CHACHA20_ENCRYPTION)
    return ChaCha20Decrypt(pCipherTextData, sCipherTextSize, pKey, pNonce, &pPlainTextData, &sPlainTextSize);
#elif defined(DES_ENCRYPTION)
    return DesDecrypt(pCipherTextData, sCipherTextSize, pKey, pIv, &pPlainTextData, &sPlainTextSize);
#elif defined(RC4_ENCRYPTION)
    return Rc4Decrypt(pRc4Key, pPayloadData, dwRc4KeySize, sPayloadSize);
#elif defined(RSA_ENCRYPTION)
    return RsaDecrypt(pCipherTextData, sCipherTextSize, pPrivateKey, sPrivateKeySize, &pPlainTextData, &sPlainTextSize);
#elif defined(XOR_ENCRYPTION)
    return XorDecrypt(pShellcode, sShellcodeSize, bKey, sKeySize);
#endif

    return FALSE;
}

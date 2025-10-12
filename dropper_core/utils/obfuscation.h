#ifndef OBFUSCATION_H
#define OBFUSCATION_H

#include "../common.h"

BOOL deobfuscatePayload(IN PBYTE Payload, IN SIZE_T PayloadSize, OUT PBYTE *pDecryptedPayload, OUT SIZE_T *dwDecryptedPayloadSize);

#endif
    
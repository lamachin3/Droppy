#include "encoders.h"


BOOL deobfuscate(IN CHAR * ShellcodeArray[], IN SIZE_T NmbrOfElements, OUT PBYTE * ppDAddress, OUT SIZE_T * pDSize) {
#if defined(IPV4_OBFUSCATION)
    return Ipv4Deobfuscation(ShellcodeArray, NmbrOfElements, ppDAddress, pDSize);
#elif defined(IPV6_OBFUSCATION)
    return Ipv6Deobfuscation(ShellcodeArray, NmbrOfElements, ppDAddress, pDSize);
#elif defined(MAC_OBFUSCATION)
    return MacDeobfuscation(ShellcodeArray, NmbrOfElements, ppDAddress, pDSize);
#elif defined(UUID_OBFUSCATION)
    return UuidDeobfuscation(ShellcodeArray, NmbrOfElements, ppDAddress, pDSize);
#endif

    return FALSE;
}
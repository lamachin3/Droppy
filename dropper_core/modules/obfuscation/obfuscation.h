#ifndef OBFUSCATION_H
#define OBFUSCATION_H

#include "../../common.h"

/**
 * @brief Deobfuscates an IPv4 address from an array of characters.
 *
 * This function takes an array of character pointers representing an obfuscated IPv4 address
 * and the number of elements in the array. It deobfuscates the address and returns it in the
 * form of a byte array along with its size.
 *
 * @param Ipv4Array An array of character pointers where each pointer points to a part of the
 *                  obfuscated IPv4 address.
 * @param NmbrOfElements The number of elements in the Ipv4Array.
 * @param ppDAddress A pointer to a byte pointer where the deobfuscated IPv4 address will be stored.
 * @param pDSize A pointer to a SIZE_T where the size of the deobfuscated address will be stored.
 *
 * @return TRUE if the deobfuscation is successful, FALSE otherwise.
 * 
 * @name IPV4 Obfuscation
 */
BOOL Ipv4Deobfuscation(IN CHAR * Ipv4Array[], IN SIZE_T NmbrOfElements, OUT PBYTE * ppDAddress, OUT SIZE_T * pDSize);

/**
 * @brief Deobfuscates an IPv6 address from an array of characters.
 *
 * This function takes an array of character pointers representing an obfuscated IPv6 address
 * and the number of elements in the array. It deobfuscates the address and returns it in the
 * form of a byte array along with its size.
 *
 * @param Ipv6Array An array of character pointers where each pointer points to a part of the
 *                  obfuscated IPv6 address.
 * @param NmbrOfElements The number of elements in the Ipv6Array.
 * @param ppDAddress A pointer to a byte pointer where the deobfuscated IPv6 address will be stored.
 * @param pDSize A pointer to a SIZE_T where the size of the deobfuscated address will be stored.
 *
 * @return TRUE if the deobfuscation is successful, FALSE otherwise.
 * 
 * @name IPV6 Obfuscation
 */
BOOL Ipv6Deobfuscation(IN CHAR* Ipv6Array[], IN SIZE_T NmbrOfElements, OUT PBYTE * ppDAddress, OUT SIZE_T * pDSize);

/**
 * @brief Deobfuscates a MAC address from an array of characters.
 *
 * This function takes an array of character pointers representing an obfuscated MAC address
 * and the number of elements in the array. It deobfuscates the address and returns it in the
 * form of a byte array along with its size.
 *
 * @param MacArray An array of character pointers where each pointer points to a part of the
 *                 obfuscated MAC address.
 * @param NmbrOfElements The number of elements in the MacArray.
 * @param ppDAddress A pointer to a byte pointer where the deobfuscated MAC address will be stored.
 * @param pDSize A pointer to a SIZE_T where the size of the deobfuscated address will be stored.
 *
 * @return TRUE if the deobfuscation is successful, FALSE otherwise.
 * 
 * @name MAC Obfuscation
 */
BOOL MacDeobfuscation(IN CHAR* MacArray[], IN SIZE_T NmbrOfElements, OUT PBYTE * ppDAddress, OUT SIZE_T * pDSize);

/**
 * @brief Deobfuscates a UUID from an array of characters.
 *
 * This function takes an array of character pointers representing an obfuscated UUID
 * and the number of elements in the array. It deobfuscates the UUID and returns it in the
 * form of a byte array along with its size.
 *
 * @param UuidArray An array of character pointers where each pointer points to a part of the
 *                  obfuscated UUID.
 * @param NmbrOfElements The number of elements in the UuidArray.
 * @param ppDAddress A pointer to a byte pointer where the deobfuscated UUID will be stored.
 * @param pDSize A pointer to a SIZE_T where the size of the deobfuscated UUID will be stored.
 *
 * @return TRUE if the deobfuscation is successful, FALSE otherwise.
 * 
 * @name UUID Obfuscation
 */
BOOL UuidDeobfuscation(IN CHAR* UuidArray[], IN SIZE_T NmbrOfElements, OUT PBYTE * ppDAddress, OUT SIZE_T * pDSize);

#endif
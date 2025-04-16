import os
from Crypto.Cipher import AES, ARC4
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes


obfuscation_algorithms = ["ipv4", "ipv6", "mac", "uuid"]


def xor_encrypt(data: bytearray) -> tuple[bytearray, bytes]:
    shellcode = bytearray(data)
    shellcode_size = len(shellcode)
    
    # Generate a random key
    key_size = 8
    key = os.urandom(key_size)
    
    for i in range(shellcode_size):
        shellcode[i] ^= key[i % key_size]  # XOR with cyclic key index

    return bytes(shellcode), key  # Return encrypted shellcode and key

def aes_encrypt(data):
    # Generate a random 256-bit key for AES encryption (32 bytes)
    key = get_random_bytes(32)
    # Generate a random initialization vector (IV) for AES encryption (16 bytes)    
    iv = get_random_bytes(16)
    
    # Create the AES cipher object using the CBC mode
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Encrypt the data
    ciphertext = cipher.encrypt(pad(data, AES.block_size))
    
    # Return the encrypted data, the key and the initialization vector used
    return ciphertext, key, iv

def rc4_encrypt(payload_data: bytes) -> tuple[bytes, bytes]:
    """
    Encrypts data using RC4 (equivalent to SystemFunction032 in Windows).
    
    :param payload_data: The payload to be encrypted
    :param key_size: The size of the RC4 key in bytes (default: 16)
    :return: Tuple containing (encrypted_data, rc4_key)
    """
    # Generate a random RC4 key
    rc4_key = os.urandom(16)
    
    # Create an RC4 cipher object with the generated key
    cipher = ARC4.new(rc4_key)
    
    # Encrypt the payload
    encrypted_data = cipher.encrypt(payload_data)
    
    return encrypted_data, rc4_key

def ipv4_encoding(payload_data: bytes) -> list[str]:
    """
    Convert a byte array to multiple IPv4 addresses. Each IPv4 address is represented by 4 bytes.
    If the byte array length is not a multiple of 4, it will be padded with 0x00.
    
    Args:
        byte_array (list of int): A list of byte values.
        
    Returns:
        list of str: A list of IPv4 addresses in dotted decimal format.
    """
    if not payload_data:
        return []

    byte_array = bytearray(payload_data)

    # Pad with 0x00 to ensure length is a multiple of 4
    missing_bytes = len(byte_array) % 4
    while len(byte_array) % 4 != 0:
        byte_array.insert(-missing_bytes, 0x00)

    return [
        f"{byte_array[i]}.{byte_array[i+1]}.{byte_array[i+2]}.{byte_array[i+3]}"
        for i in range(0, len(byte_array), 4)
    ]

def ipv6_encoding(payload_data: bytes) -> list[str]:
    """
    Convert a byte array to multiple IPv6 addresses. Each IPv6 address is represented by 16 bytes.
    If the byte array length is not a multiple of 16, it will be padded with 0x00.
    
    Args:
        byte_array (list of int): A list of byte values.
        
    Returns:
        list of str: A list of IPv6 addresses in colon-separated hexadecimal format.
    """
    if not payload_data:
        return []

    byte_array = bytearray(payload_data)

    # Pad with 0x00 to ensure length is a multiple of 16
    missing_bytes = len(byte_array) % 16
    while len(byte_array) % 16 != 0:
        byte_array.insert(-missing_bytes, 0x00)

    return [
        ":".join(
            f"{(byte_array[i + j] << 8) + byte_array[i + j + 1]:04x}"
            for j in range(0, 16, 2)
        )
        for i in range(0, len(byte_array), 16)
    ]
    
def mac_encoding(payload_data: bytes) -> list[str]:
    if not payload_data:
        return []

    byte_array = bytearray(payload_data)

    # Pad with 0x00 to ensure length is a multiple of 6
    while len(byte_array) % 6 != 0:
        byte_array.append(0x00)

    return [
        "-".join(f"{byte_array[i + j]:02x}" for j in range(6))
        for i in range(0, len(byte_array), 6)
    ]

def uuid_encoding(payload_data: bytes) -> list[str]:
    if not payload_data:
        return []

    byte_array = bytearray(payload_data)

    # Pad with 0x00 to ensure length is a multiple of 16
    missing_bytes = len(byte_array) % 16
    while len(byte_array) % 16 != 0:
        byte_array.insert(-missing_bytes, 0x00)

    return [
        f"{byte_array[i+3]:02x}{byte_array[i+2]:02x}{byte_array[i+1]:02x}{byte_array[i]:02x}-"
        f"{byte_array[i+5]:02x}{byte_array[i+4]:02x}-{byte_array[i+7]:02x}{byte_array[i+6]:02x}-"
        f"{byte_array[i+8]:02x}{byte_array[i+9]:02x}-{byte_array[i+10]:02x}{byte_array[i+11]:02x}"
        f"{byte_array[i+12]:02x}{byte_array[i+13]:02x}{byte_array[i+14]:02x}{byte_array[i+15]:02x}"
        for i in range(0, len(byte_array), 16)
    ]


def generate_shellcode(shellcode: str, algorithm: str ='xor'):
    shellcode_bytes = bytes(int(x, 16) for x in shellcode.split(', '))
    shellcode_string = ""
    enc_key = None
    iv = None
    
    if algorithm not in obfuscation_algorithms:
        match algorithm:
            case 'xor':
                shellcode_bytes, enc_key = xor_encrypt(shellcode_bytes)
            case 'aes':
                shellcode_bytes, enc_key, iv = aes_encrypt(shellcode_bytes)
            case 'rc4':
                shellcode_bytes, enc_key = rc4_encrypt(shellcode_bytes)
        shellcode_string = ', '.join(f'0x{byte:02X}' for byte in shellcode_bytes)
    else:
        match algorithm:
            case 'ipv4':
                shellcode_string = ", ".join(ipv4_encoding(shellcode_bytes))
            case 'ipv6':
                shellcode_string = ", ".join(ipv6_encoding(shellcode_bytes))
            case 'mac':
                shellcode_string = ", ".join(mac_encoding(shellcode_bytes))
            case 'uuid':
                shellcode_string = ", ".join(uuid_encoding(shellcode_bytes))
    
    # Convert key to hex string for C code
    key_hex_string = "0x00"
    if enc_key:
        key_hex_string = ', '.join(f'0x{byte:02X}' for byte in enc_key)
        
    # Convert iv to hex string for C code
    iv_hex_string = "0x00"
    if iv:
        iv_hex_string = ', '.join(f'0x{byte:02X}' for byte in iv)
       
    return shellcode_string, key_hex_string, iv_hex_string

def format_shellcode(shellcode: str, algorithm: str) -> str:
    shellcode_list = shellcode.split(", ")
    
    if algorithm not in obfuscation_algorithms:
        formatted_shellcode = "unsigned char Payload [] = {\n\t"
        
        for i in range(0, len(shellcode_list), 24):
            line = ", ".join(byte for byte in shellcode_list[i:i+24])
            formatted_shellcode += line + ",\n\t"
    else:
        formatted_shellcode = "char* Payload [] = {\n\t"
        
        for i in range(0, len(shellcode_list), 12):
            line = ", ".join(f"\"{byte}\"" for byte in shellcode_list[i:i+12])
            formatted_shellcode += line + ",\n\t"
            
    formatted_shellcode = formatted_shellcode.rstrip(",\n\t") + "\n};"

    return formatted_shellcode

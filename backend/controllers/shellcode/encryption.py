import os
from Crypto.Cipher import AES, ARC4
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

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
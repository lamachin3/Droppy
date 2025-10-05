import os
from Crypto.Cipher import AES, ARC4
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

def xor_encrypt(data: bytearray, key: bytes = None) -> tuple[bytearray, bytes]:
    shellcode = bytearray(data)
    shellcode_size = len(shellcode)
    
    if not key:
        key_size = 8
        key = os.urandom(key_size)
    
    for i in range(shellcode_size):
        shellcode[i] ^= key[i % len(key)]  # XOR with cyclic key index

    return bytes(shellcode), key

def aes_encrypt(data: bytes, key = None, iv = None) -> tuple[bytes, bytes, bytes]:
    if not key:
        key = get_random_bytes(32)
    if not iv:
        iv = get_random_bytes(16)
    
    # Create the AES cipher object using the CBC mode
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Encrypt the data
    ciphertext = cipher.encrypt(pad(data, AES.block_size))
    
    # Return the encrypted data, the key and the initialization vector used
    return ciphertext, key, iv

def rc4_encrypt(payload_data: bytes, key = None) -> tuple[bytes, bytes]:
    if not key:
        key = os.urandom(16)
    
    # Create an RC4 cipher object with the generated key
    cipher = ARC4.new(key)
    
    # Encrypt the payload
    encrypted_data = cipher.encrypt(payload_data)
    
    return encrypted_data, key
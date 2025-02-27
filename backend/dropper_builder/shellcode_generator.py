import os
from Crypto.Cipher import AES, ARC4
from Crypto.Util.Padding import pad


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
    """Encrypt data using AES with a randomly generated key."""
    key = os.urandom(16)  # Generate a random 16-byte key for AES-128
    cipher = AES.new(key, AES.MODE_CBC)  # CBC mode
    encrypted = cipher.encrypt(pad(data, AES.block_size))  # Pad data to block size
    return cipher.iv + encrypted, key  # Return IV + encrypted data and key

def rc4_encrypt(data):
    """Encrypt data using RC4 with a randomly generated key."""
    key = os.urandom(16)  # Generate a random 16-byte key for RC4
    cipher = ARC4.new(key)
    encrypted = cipher.encrypt(data)
    return encrypted, key  # Return encrypted data and key

def generate_shellcode(shellcode, algorithm='xor'):
    match algorithm:
        case 'xor':
            shellcode_string, enc_key = xor_encrypt(shellcode)
        case _:
            shellcode_string = shellcode
            enc_key = None
    
    # Convert key to hex string for C code
    key_hex_string = ', '.join(f'0x{byte:02X}' for byte in enc_key)
       
    return shellcode_string, key_hex_string
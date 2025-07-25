from . import *

obfuscation_algorithms = ["ipv4", "ipv6", "mac", "uuid"]

def generate_shellcode(shellcode: str, algorithm: str ='xor'):
    if isinstance(shellcode, str):
        if "," in shellcode:
            shellcode_bytes = bytes(int(x, 16) for x in shellcode.split(', '))
        else:
            shellcode_bytes = shellcode.encode()
    else:
        shellcode_bytes = shellcode
        
    shellcode_string = ""
    enc_key = None
    iv = None
    
    print(f"Generating shellcode with algorithm: {algorithm}")
    
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

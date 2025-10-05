from . import *

obfuscation_algorithms = ["ipv4", "ipv6", "mac", "uuid"]

def obfuscate_shellcode(shellcode_bytes, algorithm: str ='xor', enc_key: bytes = None, enc_iv: bytes = None):
    shellcode_string = ""
    
    print(f"Obfuscating shellcode with algorithm: {algorithm}")
    
    match algorithm:
        case 'xor':
            shellcode_bytes, enc_key = xor_encrypt(shellcode_bytes, enc_key)
        case 'aes':
            shellcode_bytes, enc_key, enc_iv = aes_encrypt(shellcode_bytes, enc_key, enc_iv)
        case 'rc4':
            shellcode_bytes, enc_key = rc4_encrypt(shellcode_bytes, enc_key)
        case 'ipv4':
            shellcode_string = ", ".join(ipv4_encoding(shellcode_bytes))
        case 'ipv6':
            shellcode_string = ", ".join(ipv6_encoding(shellcode_bytes))
        case 'mac':
            shellcode_string = ", ".join(mac_encoding(shellcode_bytes))
        case 'uuid':
            shellcode_string = ", ".join(uuid_encoding(shellcode_bytes))
        case _:
            shellcode_string = ', '.join(f'0x{byte:02X}' for byte in shellcode_bytes)

    # Convert key to hex string for C code
    key_hex_string = "0x00"
    if enc_key and enc_key != "0x00":
        key_hex_string = ', '.join(f'0x{byte:02X}' for byte in enc_key)
        
    # Convert iv to hex string for C code
    iv_hex_string = "0x00"
    if enc_iv and enc_iv != "0x00":
        iv_hex_string = ', '.join(f'0x{byte:02X}' for byte in enc_iv)
    
    return shellcode_string, key_hex_string, iv_hex_string

def shellcode_to_header(shellcode: str, algorithm: str, var_name: str = "Shellcode") -> str:
    shellcode_list = shellcode.split(", ")
    
    if algorithm not in obfuscation_algorithms:
        formatted_shellcode = f"unsigned char {var_name} [] = {{\n\t"
        
        for i in range(0, len(shellcode_list), 24):
            line = ", ".join(byte for byte in shellcode_list[i:i+24])
            formatted_shellcode += line + ",\n\t"
    else:
        formatted_shellcode = f"char* {var_name} [] = {{\n\t"
        
        for i in range(0, len(shellcode_list), 12):
            line = ", ".join(f"\"{byte}\"" for byte in shellcode_list[i:i+12])
            formatted_shellcode += line + ",\n\t"
            
    formatted_shellcode = formatted_shellcode.rstrip(",\n\t") + "\n};"

    return formatted_shellcode

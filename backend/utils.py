import math
from collections import Counter

def extract_shellcode(shellcode: str, type: str):
    if type == 'exe':
        shellcode = shellcode = ', '.join(f'0x{byte:02x}' for byte in shellcode)
    
    return shellcode

def compute_pe_file_entropy(file_path):
    """
    Computes the Shannon entropy of a Windows PE (Portable Executable) file.
    :param file_path: Path to the PE file
    :return: Entropy value (0 to 8)
    """
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        
        # Count occurrences of each byte value (0-255)
        byte_counts = Counter(data)
        total_bytes = len(data)
        
        # Compute entropy using Shannon formula
        entropy = -sum((count / total_bytes) * math.log2(count / total_bytes) 
                       for count in byte_counts.values())
        
        return round(entropy, 1)
    except Exception as e:
        print(f"Error reading file: {e}")
        return None
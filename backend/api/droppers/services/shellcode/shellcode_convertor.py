import re
import io
import tempfile
import donut
import mimetypes
from django.core.files.uploadedfile import InMemoryUploadedFile


def clean_shellcode(shellcode: str):
    if isinstance(shellcode, str):
        shellcode = shellcode.replace("\n", " ")
        shellcode = shellcode.replace("\r", "")

        if "," in shellcode:
            shellcode_bytes = bytes(int(x, 16) for x in shellcode.split(', '))
        else:
            shellcode_bytes = shellcode.encode()
    else:
        shellcode_bytes = shellcode
        
    return shellcode_bytes

def file_to_shellcode(shellcode_file: InMemoryUploadedFile, params: str = ""):
    try:
        if _is_pe_file(shellcode_file):
            print("File is a PE file.")
            shellcode_file.seek(0)
            return pe_file_to_shellcode(shellcode_file.read(), params if params else "")
        
        if _is_hex_file(shellcode_file):
            print("File is a hex file.")
            shellcode_file.seek(0)
            hex_list = _normalize_hex(shellcode_file)
            shellcode = ', '.join(hex_list)
            return shellcode
        
        if _is_binary_file(shellcode_file):
            print("File is a binary file.")
            shellcode_file.seek(0)
            hex_list = _binary_to_hex(shellcode_file)
            shellcode = ', '.join(hex_list)
            return shellcode
        
        print("File type not recognized.")
        return None
        
    except Exception as e:
        print(f"Error processing file: {e}")
        return None


def get_mime_type(file: InMemoryUploadedFile):
    try:
        # Extract the filename
        filename = file.name
        if not filename:
            return None
        
        # Guess the MIME type based on the filename
        mime_type, _ = mimetypes.guess_type(filename)
        return mime_type
    except Exception as e:
        print(f"Error determining MIME type: {e}")
        return None


def _is_pe_file(shellcode_file: InMemoryUploadedFile):
    try:
        shellcode_file.seek(0)
        dos_header = shellcode_file.read(64)
        if len(dos_header) < 64 or dos_header[:2] != b'MZ':
            return False

        pe_offset = int.from_bytes(dos_header[0x3C:0x40], byteorder='little')
        shellcode_file.seek(pe_offset)
        pe_signature = shellcode_file.read(4)
        return pe_signature == b'PE\x00\x00'
    except FileNotFoundError:
        print(f"Error: File not found: {shellcode_file.filename}")
        return False
    except Exception as e:
        print(f"Error reading file: {e}")
        return False
    

def _is_hex_file(shellcode_file: InMemoryUploadedFile):
    try:
        shellcode_file.seek(0)
        content = shellcode_file.read(1024).decode('utf-8', errors='ignore')

        hex_pattern = r'(0x[0-9a-fA-F]{2})(,\s*|\s+|$)'
        hex_matches = re.findall(hex_pattern, content)

        if len(hex_matches) >= 2:
                return True
        return False
    except FileNotFoundError:
        print(f"Error: File not found: {shellcode_file.filename}")
        return False
    except Exception as e:
        print(f"Error reading file: {e}")
        return False

def _is_binary_file(shellcode_file: InMemoryUploadedFile):
    try:
        shellcode_file.seek(0)
        chunk = shellcode_file.read(128)
        
        if not chunk:
            print("Empty file or read error.")
            return False

        # Count the ratio of non-printable to printable characters
        text_characters = bytes(range(32, 127)) + b'\n\r\t\b'
        non_printable_count = sum(byte not in text_characters for byte in chunk)

        # If more than 30% of the bytes are non-printable, classify as binary
        print(f"Non-printable count: {non_printable_count}, Total bytes: {len(chunk)}, Ratio: {non_printable_count / len(chunk)}")
        return (non_printable_count / len(chunk)) > 0.3
    except Exception as e:
        print(f"Error checking file: {e}")
        return False

def _normalize_hex(shellcode_file: InMemoryUploadedFile):
    try:
        shellcode_file.seek(0)
        content = shellcode_file.read().decode('utf-8', errors='ignore')
        
        # Strip out common separators
        cleaned = re.sub(r'[^0-9a-fA-F]', '', content)
        
        # Special case: 0x prefix, extract those first
        hex_matches = re.findall(r'0x[0-9a-fA-F]+', content)
        if hex_matches:
            byte_list = []
            for match in hex_matches:
                hex_str = match[2:]  # Remove '0x'
                # Pad if odd
                if len(hex_str) % 2 != 0:
                    hex_str = '0' + hex_str
                byte_list.extend(['0x' + hex_str[i:i+2].lower() for i in range(0, len(hex_str), 2)])
            return byte_list

        # Otherwise, assume it's just a stream of hex characters
        if len(cleaned) % 2 != 0:
            cleaned = '0' + cleaned
        return ['0x' + cleaned[i:i+2].lower() for i in range(0, len(cleaned), 2)]
    except FileNotFoundError:
        print(f"Error: File not found: {shellcode_file.filename}")
        return []
    except Exception as e:
        print(f"Error reading file: {e}")
        return []


def _binary_to_hex(shellcode_file: InMemoryUploadedFile):
    try:
        shellcode_file.seek(0)
        byte_data = shellcode_file.read()
        return [f"0x{byte:02x}" for byte in byte_data]
    except FileNotFoundError:
        print(f"Error: File not found: {shellcode_file.filename}")
        return []
    except Exception as e:
        print(f"Error reading file: {e}")
        return []


def pe_file_to_shellcode(pe_bytes: bytes, params: str = ""):
    print("Creating shellcode from PE file...")
    print("Parameters:", params)
    try:
        # Create a temporary file to store the PE data
        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tmp_f:
            tmp_f.write(pe_bytes)
            donut_path = tmp_f.name.replace("\\", "/")
        
        # Generate shellcode using Donut
        shellcode = donut.create(donut_path, params=params)
        return shellcode
    except Exception as e:
        print(f"Error creating shellcode from PE: {e}")
        return None
    

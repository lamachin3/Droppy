import ast
import math
from flask import request
from collections import Counter

from dropper_builder.shellcode_generator import obfuscation_algorithms

PREPROCESSING_KEYS = [
    "encryption & obfuscation",
    "injection",
    "payload_loading",
    "syscalls",
    "unhooking",
]

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

def extract_form_data():
    form_data = {}
    for key, value in request.form.items():
        try:
            form_data[key] = ast.literal_eval(value) if value else None
        except (ValueError, SyntaxError):
            form_data[key] = value
    return form_data

def process_dropper_config(dropper_config):
    dropper_config['preprocessing_macros'] = []
    
    for key in dropper_config:
        if not key in PREPROCESSING_KEYS or dropper_config[key] == None:
            continue
        
        value = dropper_config.get(key, "")
        if isinstance(value, list):
            dropper_config['preprocessing_macros'].extend([v for v in value if v.strip()])
        elif isinstance(value, str):
            dropper_config['preprocessing_macros'].append(value.strip())
        else:
            dropper_config['preprocessing_macros'].append(value)
    if dropper_config.get("debug"):
        dropper_config['preprocessing_macros'].append("DEBUG")
    
    dropper_config['hide_console'] = dropper_config.get('hide_console')

    process_names = [p_name for p_name in request.form.getlist('process_name') if p_name.strip()]
    if process_names:
        dropper_config['process_name'] = process_names[0]
    if dropper_config.get('process_name') and not dropper_config['process_name'].endswith(".exe"):
        dropper_config['process_name'] = f"{dropper_config['process_name']}.exe"

    dropper_config['out_filename'] = f"{dropper_config.get('filename')}{dropper_config.get('file_extension')}"

def handle_shellcode_upload(files):
    if 'shellcode' in files:
        file = files['shellcode']
        if file.filename != '':
            return extract_shellcode(file.read(), file.filename.split(".")[-1])
    return None
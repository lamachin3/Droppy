import os
import shutil
import tempfile

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
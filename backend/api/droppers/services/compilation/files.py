import shutil
import tempfile
from pathlib import Path
from django.conf import settings

def setup_compilation_environment(config):
    """Set up the compilation environment and return the temp directory path."""
    temp_dir = Path(tempfile.mkdtemp(prefix='dropper_build_'))
    
    # Copy project files
    project_root = settings.BASE_DIR / '../dropper_core'
    shutil.copytree(project_root, temp_dir, dirs_exist_ok=True)
    print(f"[i] Temp dir: {temp_dir}")
    return temp_dir

def cleanup_compilation_environment(temp_dir):
    """Clean up temporary files."""
    shutil.rmtree(temp_dir, ignore_errors=True)

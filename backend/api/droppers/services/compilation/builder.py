import logging
import shutil
import subprocess
import os
from datetime import datetime
from pathlib import Path
from django.core.files import File
from django.conf import settings
from .files import setup_compilation_environment, cleanup_compilation_environment
from .setup import setup_dropper, set_precompilation_flags
from api.droppers.models import DropperModel, DropperConfigModel


logger = logging.getLogger(__name__)


class CompilationError(Exception):
    pass

class DropperBuilder:
    def __init__(self, dropper_config, dropper_type):
        self.config = dropper_config
        self.temp_dir = None
        self.type = dropper_type
        
        # Use the legacy output dir for now to maintain compatibility
        self.output_dir = Path(settings.BUILDS_DIR)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def build(self):
        try:
            # Setup environment
            self.temp_dir = setup_compilation_environment(self.config)
            
            # Analyze dependencies
            set_precompilation_flags(self.config)
            setup_dropper(self.temp_dir, self.config)
            
            # Run compilation
            compilation_result = self._run_compilation()

            if compilation_result['success']:
                dropper = self._store_dropper_in_db(compilation_result)
                return dropper
            
        except Exception as e:
            logger.error(f"Build failed: {str(e)}", exc_info=True)
            raise CompilationError(f"Build failed: {str(e)}")
        finally:
            if self.temp_dir and settings.CLEANUP_TEMP_FILES:
                cleanup_compilation_environment(self.temp_dir)

    def _run_compilation(self):
        # Build command with proper escaping
        command = [
            "make",
            "-f", "Makefile",
            f"-j{settings.COMPILATION_JOBS or 1}",
            f"OUTPUT_FILE={self.config['filename']}{self.config['file_extension']}",
            f"DEBUG={'true' if self.config.get('debug_mode') else 'false'}",
            f"HIDE_CONSOLE={'true' if self.config.get('hide_console') else 'false'}"
        ]
        print("[i] Running compilation command: ", command)
        
        try:
            result = subprocess.run(
                command,
                cwd=str(self.temp_dir),
                capture_output=True,
                text=True,
                check=True
            )
            
            output_path = f"{self.temp_dir}/bin/{self.config['filename']}{self.config['file_extension']}"

            #print("\n========== DEBUG - STDOUT ==========\n", result.stdout)
            #print("\n========== DEBUG - STDERR ==========\n", result.stderr)

            return {
                'success': True,
                'output_path': str(output_path),
                'stdout': result.stdout,
                'stderr': result.stderr
            }
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Compilation failed: {e.stderr}")
            raise CompilationError(f"Compilation failed: {e.stderr}")

    def _store_dropper_in_db(self, compilation_result):
        """Store the compiled dropper in the database and move to build directory."""
        try:
            # Get the output file from the compilation result
            file_name = compilation_result.get('output_path', '').split("/")[-1]
            output_path = Path(compilation_result.get('output_path', ''))
            target_file = settings.BUILDS_DIR / file_name
            
            # Create database entry with file info
            with open(output_path, 'rb') as f:
                dropper_file = File(f, name=target_file.name)
                config = DropperConfigModel.objects.create(
                    name=f"{self.config['filename']}_profile",
                    description=f"{self.config['filename']} profile",
                    dropper_type=self.type,
                    debug_mode=self.config.get('debug', False),
                    hide_console=self.config.get('hide_console', False),
                    redirect_output=self.config.get('redirect_output', False),
                    remote_process_name=self.config.get('remote_process_name', None),
                    output_extension=self.config.get('file_extension', None),
                )
                for key, value in self.config.items():
                    if key in DropperConfigModel.__dict__:
                        setattr(config, key, value)
                config.save()
                
                dropper = DropperModel(
                    file=dropper_file,
                    filename=target_file.name,
                    config=config,
                    strings_results=None,
                    yara_results=None,
                    vt_results=None,
                )
                dropper.save()

                print(f"[i] Dropper data saved to database: {config.__dict__}")
                
                # Update the compilation result with the download URL
                compilation_result['download_url'] = f'/api/core/builds/download/{target_file.name}'
                compilation_result['filename'] = target_file.name
                
            return dropper
            
        except Exception as e:
            logger.error(f"Failed to store dropper: {str(e)}", exc_info=True)
            raise

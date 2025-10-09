import os
import shutil
import tempfile
import requests
import zipfile
from pathlib import Path
from tqdm import tqdm
from django.core.management.base import BaseCommand
from django.conf import settings


YARA_RULES_URL = "https://github.com/elastic/protections-artifacts/archive/refs/heads/main.zip"
YARA_RULES_DIR = os.path.join(settings.BASE_DIR, 'api/analysis/services/yara_rules/rules/')

class Command(BaseCommand):
    help = 'Download and update YARA rules from Elastic Protections repository'

    def add_arguments(self, parser):
        parser.add_argument(
            '--force',
            action='store_true',
            help='Force update even if the repository is up to date',
        )

    def download_file(self, url, dest_path):
        """Download a file with progress bar."""
        response = requests.get(url, stream=True)
        response.raise_for_status()
        
        total_size = int(response.headers.get('content-length', 0))
        block_size = 1024 * 1024  # 1MB
        
        with open(dest_path, 'wb') as f, tqdm(
            desc=os.path.basename(dest_path),
            total=total_size,
            unit='iB',
            unit_scale=True,
            unit_divisor=1024,
        ) as bar:
            for data in response.iter_content(block_size):
                size = f.write(data)
                bar.update(size)

    def find_rules_dir(self, temp_dir):
        for root, dirs, files in os.walk(temp_dir):
            for file in files:
                if file.endswith('.yar') or file.endswith('.yara'):
                    return root
        return None

    def handle(self, *args, **options):
        force = options.get('force', False)
        self.stdout.write('Updating YARA rules...')
        
        # Create temporary directory
        with tempfile.TemporaryDirectory() as temp_dir:
            zip_path = os.path.join(temp_dir, 'archive.zip')
            
            try:
                # Download the repository
                self.stdout.write(f'Downloading YARA rules from {YARA_RULES_URL}...')
                self.download_file(YARA_RULES_URL, zip_path)
                
                # Extract the zip file
                self.stdout.write('Extracting YARA rules...')
                with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                    # Get list of files with progress
                    members = zip_ref.namelist()
                    for member in tqdm(members, desc='Extracting'):
                        try:
                            zip_ref.extract(member, temp_dir)
                        except Exception as e:
                            self.stderr.write(f'Error extracting {member}: {str(e)}')
                
                # Find the rules directory
                extracted_dir = self.find_rules_dir(temp_dir)
                if not os.path.exists(extracted_dir):
                    raise Exception('Could not find YARA rules in the downloaded repository')
                
                # Create target directory if it doesn't exist
                os.makedirs(YARA_RULES_DIR, exist_ok=True)
                
                # Copy the rules
                self.stdout.write(f'Copying YARA rules to {YARA_RULES_DIR}...')
                rules_count = 0
                
                # First, remove all existing .yara and .yar files if force is True
                if force:
                    for ext in ('*.yara', '*.yar'):
                        for old_file in Path(YARA_RULES_DIR).glob(ext):
                            try:
                                old_file.unlink()
                            except Exception as e:
                                self.stderr.write(f'Error removing old rule {old_file}: {str(e)}')
                
                # Copy new rules
                for root, _, files in os.walk(extracted_dir):
                    for file in files:
                        if file.endswith(('.yara', '.yar')):
                            src_path = os.path.join(root, file)
                            rel_path = os.path.relpath(src_path, extracted_dir)
                            dest_path = os.path.join(YARA_RULES_DIR, os.path.basename(file))
                            
                            # Skip if file exists and is the same
                            if not force and os.path.exists(dest_path):
                                if os.path.getmtime(src_path) <= os.path.getmtime(dest_path):
                                    continue
                            
                            try:
                                shutil.copy2(src_path, dest_path)
                                rules_count += 1
                            except Exception as e:
                                self.stderr.write(f'Error copying {file}: {str(e)}')
                
                if rules_count > 0:
                    self.stdout.write(self.style.SUCCESS(f'Successfully updated {rules_count} YARA rules'))
                
            except requests.RequestException as e:
                self.stderr.write(self.style.ERROR(f'Error downloading YARA rules: {str(e)}'))
            except zipfile.BadZipFile:
                self.stderr.write(self.style.ERROR('Error: Downloaded file is not a valid zip archive'))
            except Exception as e:
                self.stderr.write(self.style.ERROR(f'Error: {str(e)}'))

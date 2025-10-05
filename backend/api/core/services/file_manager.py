import os
from pathlib import Path
from datetime import datetime
from typing import List, Optional
from dataclasses import dataclass
from django.core.exceptions import ObjectDoesNotExist
from api.core.models.file_model import FileModel
from django.conf import settings


@dataclass
class FileObject:
    """Represents a file in the storage."""
    name: str
    path: str
    size: int
    created_at: datetime


class FileManager:
    def __init__(self, storage_dir: str = None):
        if storage_dir is None:
            self.storage_dir = settings.BUILDS_DIR
        else:
            self.storage_dir = storage_dir
            
        os.makedirs(self.storage_dir, exist_ok=True)
    
    def get_file_path(self, filename: str) -> str:
        return os.path.join(self.storage_dir, filename)
    
    def list_files(self) -> List[FileObject]:
        """List all files in the storage directory.
        
        Returns:
            List of FileObject objects
        """
        files = []
        try:
            for entry in os.scandir(self.storage_dir):
                if entry.is_file() and not entry.name.startswith('.'):
                    stat = entry.stat()
                    files.append(FileObject(
                        name=entry.name,
                        path=entry.path,
                        size=stat.st_size,
                        created_at=datetime.fromtimestamp(stat.st_ctime)
                    ))
        except FileNotFoundError:
            # Directory doesn't exist yet, return empty list
            pass
            
        return sorted(files, key=lambda x: x.created_at, reverse=True)
    
    def get_file(self, filename_or_id: str) -> Optional[FileObject]:
        try:
            file = FileModel.objects.get(id=filename_or_id) or FileModel.objects.get(name=filename_or_id)
            if file is None:
                return None

            return FileObject(
                name=file.filename,
                path=file.file.url,
                size=file.size,
                created_at=file.created_at
            )
        except ObjectDoesNotExist:
            return None
    
    def save_file(self, file_obj, filename: str) -> bool:
        """Save a file to the storage directory.
        
        Args:
            file_obj: File-like object to save
            filename: Name to save the file as
            
        Returns:
            True if successful, False otherwise
        """
        try:
            filepath = self.get_file_path(filename)
            with open(filepath, 'wb+') as destination:
                for chunk in file_obj.chunks():
                    destination.write(chunk)
            return True
        except OSError:
            return False
    
    def delete_file(self, filename: str) -> bool:
        """Delete a file from the storage directory.
        
        Args:
            filename: Name of the file to delete
            
        Returns:
            True if successful, False otherwise
        """
        try:
            filepath = self.get_file_path(filename)
            os.remove(filepath)
            return True
        except OSError:
            return False

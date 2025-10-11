import uuid
import hashlib
import os
from datetime import datetime
from django.db import models
from django.conf import settings
from django.core.files.base import ContentFile
from django.core.files.storage import default_storage
from polymorphic.models import PolymorphicModel
from api.core.services.file_storage import FileStorage


def safe_filename(instance, filename):
    os.makedirs(settings.BUILDS_DIR, exist_ok=True)
    upload_path = os.path.join(settings.BUILDS_DIR, filename)
    
    if os.path.exists(upload_path):
        base, ext = os.path.splitext(filename)
        filename = f'{base}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.{ext}'
   
    return filename

class FileModel(PolymorphicModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    file = models.FileField(upload_to=safe_filename, storage=FileStorage())
    filename = models.CharField(max_length=255, unique=True)
    size = models.FloatField()
    md5_hash = models.CharField(max_length=255)
    sha1_hash = models.CharField(max_length=255)
    sha256_hash = models.CharField(max_length=255)

    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.CharField(max_length=255, null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)
    updated_by = models.CharField(max_length=255, null=True, blank=True)

    def save(self, *args, **kwargs):
        # Only update file-related fields if the file has changed
        if self.file and (not self.pk or self._state.adding or self.__class__.objects.get(pk=self.pk).file != self.file):

            # Calculate file size in Bytes
            self.size = self.file.size
            
            # Calculate hashes
            pos = self.file.tell()
            self.file.seek(0)
            
            # Read file in chunks to handle large files
            md5_hash = hashlib.md5()
            sha1_hash = hashlib.sha1()
            sha256_hash = hashlib.sha256()
                
            for chunk in self.file.chunks():
                md5_hash.update(chunk)
                sha1_hash.update(chunk)
                sha256_hash.update(chunk)
                
            # Store hashes
            self.md5_hash = md5_hash.hexdigest()
            self.sha1_hash = sha1_hash.hexdigest()
            self.sha256_hash = sha256_hash.hexdigest()
            
            # Reset file pointer
            self.file.seek(pos)
        
        super().save(*args, **kwargs)
    
    def __str__(self):
        return self.filename
    
    def delete(self, *args, **kwargs):
        if self.file:
            if default_storage.exists(self.file.name):
                default_storage.delete(self.file.name)
        super().delete(*args, **kwargs)
        
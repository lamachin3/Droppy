from django.core.files.storage import FileSystemStorage
from django.conf import settings

class FileStorage(FileSystemStorage):
    def __init__(self, location=None, base_url=None):
        location = settings.BUILDS_DIR
        super().__init__(location, base_url)
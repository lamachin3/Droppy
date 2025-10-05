import requests
from io import BytesIO
from django.core.files.uploadedfile import InMemoryUploadedFile


def fetch_github_ressource(url: str) -> InMemoryUploadedFile:
    print(f"Fetching ressource from GitHub URL: {url}")
    github_data = requests.get(url, stream=True)

    file_content = BytesIO(github_data.content)
    file_name = url.split('/')[-1] or 'github_file'

    return InMemoryUploadedFile(
        file=file_content,
        field_name='file',
        name=file_name,
        content_type=github_data.headers.get('content-type', 'application/octet-stream'),
        size=len(github_data.content),
        charset=None
    )

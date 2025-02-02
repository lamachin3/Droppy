import os

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "your_default_secret_key")
    DEBUG = os.getenv("DEBUG", "True") == "True"
    OUTPUT_FOLDER = os.getenv("OUTPUT_FOLDER", "static/outputs")

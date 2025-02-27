from flask import Flask
from routes import init_routes
from config import Config
import os

def create_app():
    app = Flask(__name__)

    # Load configurations from config.py
    app.config.from_object(Config)
    app.allowed_extensions = {'exe', 'dll', 'bin'}
    
    if not os.path.exists(app.config['OUTPUT_FOLDER']):
        os.makedirs(app.config['OUTPUT_FOLDER'])

    # Initialize routes from routes.py
    init_routes(app)

    return app

if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=8000, debug=True)

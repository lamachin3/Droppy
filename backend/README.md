# Dropper API

Django REST API for the Dropper application.

## Setup

1. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Create a `.env` file in the root directory with the following variables:
   ```
   DJANGO_SECRET_KEY=your-secret-key
   DEBUG=True
   DJANGO_ENV=development
   ```

4. Run migrations:
   ```bash
   python manage.py migrate
   ```

5. Create a superuser:
   ```bash
   python manage.py createsuperuser
   ```

6. Run the development server:
   ```bash
   python manage.py runserver
   ```

## Project Structure

```
backend/
├── api/                      # Main API package
│   ├── analysis/             # File analysis functionality
│   ├── config/               # Project configuration
│   ├── core/                 # Core functionality
│   ├── dropper_builder/      # Dropper building functionality
│   └── users/                # User management
├── manage.py
└── requirements.txt
```

## API Documentation

After starting the server, you can access:
- API Schema: http://127.0.0.1:8000/api/schema/
- Swagger UI: http://127.0.0.1:8000/api/schema/swagger-ui/
- ReDoc: http://127.0.0.1:8000/api/schema/redoc/

## Development

- Use `DJANGO_ENV=development` for development settings
- Run tests with `python manage.py test`

## Production

- Set `DJANGO_ENV=production`
- Configure all required environment variables
- Use a production WSGI server (e.g., Gunicorn, uWSGI)

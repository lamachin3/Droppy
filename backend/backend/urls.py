from django.contrib import admin
from django.urls import path, include
from drf_spectacular.views import (
    SpectacularAPIView,
    SpectacularRedocView,
    SpectacularSwaggerView,
)

urlpatterns = [
    # Django Admin
    path('admin/', admin.site.urls),
    
    # API Authentication
    path('api/auth/', include('api.auth.urls')),  # User authentication endpoints

    # API Core
    path('api/', include('api.core.urls')),  # Core functionality endpoints
    
    # API Dropper Builder
    path('api/dropper/', include('api.droppers.urls')),  # Dropper builder endpoints
    
    # API Analysis
    path('api/analysis/', include('api.analysis.urls')),  # Analysis endpoints
    
    # API Users
    path('api/users/', include('api.users.urls')),  # User endpoints
    
    # API Auth
    path('api-auth/', include('rest_framework.urls')),  # For browsable API
    
    # API Schema and Documentation
    path('api/schema/', SpectacularAPIView.as_view(), name='schema'),
    
    # Swagger UI
    path('api/docs/swagger/', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger-ui'),
    
    # ReDoc
    path('api/docs/redoc/', SpectacularRedocView.as_view(url_name='schema'), name='redoc'),
]

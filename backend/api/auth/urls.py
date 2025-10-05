from django.urls import path
from .views import LoginView, LogoutView, CheckAuthView, CSRFView

urlpatterns = [
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    
    path('check-auth/', CheckAuthView.as_view(), name='check-auth'),
    
    path('csrf/', CSRFView.as_view(), name='csrf'),
]

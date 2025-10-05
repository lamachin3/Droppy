from django.urls import path
from .views import AdvancedDropperView, BasicDropperView, CompileDropperView, DropperConfigTemplateViewSet


app_name = 'droppers'

urlpatterns = [
    path('build/', CompileDropperView.as_view(), name='build_dropper'),
    path('advanced/', AdvancedDropperView.as_view(), name='advanced_dropper'),
    path('basic/', BasicDropperView.as_view(), name='basic_dropper'),
    path('dropper_templates/', DropperConfigTemplateViewSet.as_view({'get': 'list', 'delete': 'destroy', 'post': 'create'}), name='dropper_config'),
    path('dropper_templates/<uuid:pk>/', DropperConfigTemplateViewSet.as_view({'get': 'retrieve'}), name='dropper_config_retrieve'),
    path('dropper_templates/<uuid:pk>/toggle/', DropperConfigTemplateViewSet.as_view({'post': 'toggle'}), name='dropper_config_toggle'),
    path('dropper_templates/<uuid:pk>/rename/', DropperConfigTemplateViewSet.as_view({'post': 'rename'}), name='dropper_config_rename'),
    path('dropper_templates/<uuid:pk>/download/', DropperConfigTemplateViewSet.as_view({'get': 'download'}), name='dropper_config_download'),
]

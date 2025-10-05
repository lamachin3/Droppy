from django.contrib import admin
from django.apps import apps

# Import models using the app registry to avoid circular imports
FileModel = apps.get_model('core', 'FileModel')
DropperModel = apps.get_model('droppers', 'DropperModel')
DropperConfigModel = apps.get_model('droppers', 'DropperConfigModel')

class FileModelAdmin(admin.ModelAdmin):
    list_display = ('filename', 'size', 'md5_hash', 'created_at', 'created_by')
    list_filter = ('created_at',)
    search_fields = ('filename', 'md5_hash', 'sha1_hash', 'sha256_hash')
    readonly_fields = ('size', 'md5_hash', 'sha1_hash', 'sha256_hash', 'created_at', 'updated_at')
    fieldsets = (
        ('File Information', {
            'fields': ('file', 'filename', 'size')
        }),
        ('Hashes', {
            'fields': ('md5_hash', 'sha1_hash', 'sha256_hash'),
            'classes': ('collapse',)
        }),
        ('Metadata', {
            'fields': ('created_at', 'created_by', 'updated_at', 'updated_by'),
            'classes': ('collapse',)
        }),
    )

class DropperConfigModelAdmin(admin.ModelAdmin):
    list_display = ('id', 'created_at', 'created_by')
    list_filter = ('created_at',)
    search_fields = ('created_by__username',)
    readonly_fields = ('dropper_type', 'created_at', 'updated_at')
    fieldsets = (
        ('General', {
            'fields': ('dropper_type', 'name', 'description', 'is_template')
        }),
        ('Configuration', {
            'fields': ('amsi_bypass', 'etw_bypass', 'injector', 'loader', 
                      'obfuscation', 'unhooking', 'syscalls')
        }),
        ('Metadata', {
            'fields': ('created_at', 'created_by', 'updated_at'),
            'classes': ('collapse',)
        }),
    )

class DropperModelAdmin(admin.ModelAdmin):
    list_display = ('filename', 'size', 'get_injector_type', 'get_loader_type', 'created_at')
    list_filter = ('created_at', )
    search_fields = ('filename', 'md5_hash', 'sha1_hash', 'sha256_hash')
    readonly_fields = ('size', 'md5_hash', 'sha1_hash', 'sha256_hash', 'created_at', 'updated_at')
    
    def get_injector_type(self, obj):
        return obj.config.injector if obj.config else None
    get_injector_type.short_description = 'Injector Type'
    get_injector_type.admin_order_field = 'config__injector'
    
    def get_loader_type(self, obj):
        return obj.config.loader if obj.config else None
    get_loader_type.short_description = 'Loader Type'
    get_loader_type.admin_order_field = 'config__loader'
    
    fieldsets = (
        ('File Information', {
            'fields': ('file', 'filename', 'size')
        }),
        ('Dropper Configuration', {
            'fields': ('config',)
        }),
        ('Analysis Results', {
            'fields': ('strings_results', 'yara_results', 'vt_results'),
            'classes': ('collapse',)
        }),
        ('Hashes', {
            'fields': ('md5_hash', 'sha1_hash', 'sha256_hash'),
            'classes': ('collapse',)
        }),
        ('Metadata', {
            'fields': ('created_at', 'created_by', 'updated_at', 'updated_by'),
            'classes': ('collapse',)
        }),
    )
    
    def get_queryset(self, request):
        return super().get_queryset(request).select_related(
            'config', 'strings_results', 'yara_results', 'vt_results'
        )

# Register models
admin.site.register(FileModel, FileModelAdmin)
admin.site.register(DropperModel, DropperModelAdmin)
admin.site.register(DropperConfigModel, DropperConfigModelAdmin)

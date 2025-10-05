from rest_framework import serializers
from api.core.models.file_model import FileModel

class FileModelSerializer(serializers.ModelSerializer):
    """
    Base serializer for FileModel and its subclasses.
    Handles common fields and dynamic field inclusion based on model type.
    """
    model = serializers.SerializerMethodField()
    download_url = serializers.SerializerMethodField()
    details_url = serializers.SerializerMethodField()
    
    class Meta:
        model = FileModel
        fields = [
            'id', 'model', 'filename', 'size', 
            'md5_hash', 'sha1_hash', 'sha256_hash',
            'created_at', 'download_url', 'details_url'
        ]
        read_only_fields = fields
    
    def get_model(self, obj):
        """Get the model class name of the object."""
        return obj.__class__.__name__
    
    def get_download_url(self, obj):
        """Generate download URL for the file."""
        request = self.context.get('request')
        if request:
            return request.build_absolute_uri(f'/api/builds/{obj.id}/download/')
        return None
    
    def get_details_url(self, obj):
        """Generate details URL for the file."""
        request = self.context.get('request')
        if request:
            return request.build_absolute_uri(f'/api/builds/{obj.id}/')
        return None
    
    def to_representation(self, instance):
        """
        Override to include model-specific fields dynamically.
        """
        representation = super().to_representation(instance)
        
        # Add model-specific fields
        if hasattr(instance, 'config') and instance.config:
            representation['config'] = str(instance.config.id)
        
        # Add analysis flags if they exist
        for field in ['strings_results', 'yara_results', 'vt_results']:
            if hasattr(instance, field) and getattr(instance, field):
                representation[f'has_{field}'] = True
        
        return representation


class FileModelDetailsSerializer(FileModelSerializer):
    """
    Serializer for FileModel and its subclasses with additional details.
    """
    class Meta:
        model = FileModel
        fields = FileModelSerializer.Meta.fields + [
            'config', 'strings_results', 'yara_results', 'vt_results'
        ]
        read_only_fields = fields

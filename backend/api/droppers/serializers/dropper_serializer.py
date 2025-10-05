import os
from rest_framework import serializers
from django.conf import settings
from api.droppers.models import DropperModel, DropperConfigModel
from api.droppers.services.data_enrichment import DataEnrichmentService
from api.analysis.services import YaraEngine, StringEngine, VirusTotalEngine
from api.droppers.services.github import fetch_exegol_executables


FEATURES_KEYS = [
    'anti_analysis',
    'anti_debug',
    'anti_vm',
    'amsi_bypass',
    'etw_bypass',
    'injector',
    'loader',
    'obfuscation',
    'unhooking',
    'syscalls',
    'binary_signing_enabled',
    'certificate_file',
    'certificate_password',
]

class BasicDropperRequestSerializer(serializers.Serializer):
    """Serializer for the basic dropper build request."""
    # Core features
    local_injection = serializers.BooleanField(default=True, required=False)
    remote_injection = serializers.BooleanField(default=True, required=False)
    loader = serializers.BooleanField(default=True, required=False)
    obfuscation = serializers.BooleanField(default=False, required=False)
    amsi_bypass = serializers.BooleanField(default=False, required=False)
    etw_bypass = serializers.BooleanField(default=False, required=False)
    unhooking = serializers.BooleanField(default=False, required=False)
    syscalls = serializers.BooleanField(default=False, required=False)
    
    # Options
    debug_mode = serializers.BooleanField(default=False, required=False)
    hide_console = serializers.BooleanField(default=True, required=False)
    redirect_output = serializers.BooleanField(default=False, required=False)
    remote_process_name = serializers.CharField(required=False, allow_blank=True)
    
    # Input (only one of these is required)
    shellcode_text = serializers.CharField(required=False, allow_blank=True)
    shellcode = serializers.FileField(required=False, allow_null=True)
    github_url = serializers.URLField(required=False, allow_blank=True)
    
    # Additional options
    execution_args = serializers.CharField(required=False, allow_blank=True)
    remote_process_name = serializers.CharField(required=False, allow_blank=True)
    filename = serializers.CharField(required=False, allow_blank=True)
    file_extension = serializers.ChoiceField(
        choices=['.exe'], 
        default='.exe', 
        required=False
    )
    
    def validate(self, data):
        if data.get('local_injection') and data.get('remote_injection'):
            raise serializers.ValidationError(
                "Only one of 'local_injection' or 'remote_injection' can be enabled."
            )

        if not any(data.get(field) for field in ['shellcode_text', 'shellcode', 'github_url']):
            raise serializers.ValidationError(
                "At least one of 'shellcode_text', 'shellcode', or 'github_url' must be provided."
            )
        return data
    
    def to_internal_value(self, data):
        """Convert the input data to the internal representation."""
        # Handle file uploads
        if 'shellcode' in data and hasattr(data['shellcode'], 'file'):
            # This is a file upload, keep it as is
            pass
        return super().to_internal_value(data)
    
    def to_representation(self, instance):
        """Convert the internal representation to the output format."""
        # This is a write-only serializer, so we don't need to implement this
        return {}


class BasicDropperResponseSerializer(serializers.Serializer):
    """Serializer for the basic dropper GET response."""
    features = serializers.SerializerMethodField()
    options = serializers.SerializerMethodField()
    input = serializers.SerializerMethodField()
    output = serializers.SerializerMethodField()
    
    def get_features(self, obj):
        return [
            {'name': 'local_injection', 'label': 'Local Injection', 'required': True, 'description': 'Inject the payload into the current process'},
            {'name': 'remote_injection', 'label': 'Remote Injection', 'required': True, 'description': 'Inject the payload into a remote process'},
            {'name': 'loader', 'label': 'Stealthy Payload Loading', 'required': True, 'description': 'Load the payload in stealthier way'},
            {'name': 'obfuscation', 'label': 'Payload Obfuscation', 'required': False, 'description': 'Obfuscation the payload to be less detectable by static analysis'},
            {'name': 'amsi_bypass', 'label': 'AMSI Bypass', 'required': False, 'description': 'Implement Anti Malware Scan Interface (AMSI) bypass technique'},
            {'name': 'etw_bypass', 'label': 'ETW Bypass', 'required': False, 'description': 'Implement Event Tracing for Windows (ETW) bypass technique'},
            {'name': 'unhooking', 'label': 'EDR/AV Unhooking', 'required': False, 'description': 'Implement EDR/AV unhooking technique'},
            {'name': 'syscalls', 'label': 'Syscalls', 'required': False, 'description': 'Use Syscalls instead of Windows API calls'},
        ]
    
    def get_options(self, obj):
        return [
            {'value': 'debug_mode', 'label': 'Debug Mode', 'description': 'Enable debug mode for troubleshooting'},
            {'value': 'hide_console', 'label': 'Hide Console', 'description': 'Hide the console window during execution'},
            {'value': 'redirect_output', 'label': 'Redirect Output', 'description': 'Redirect output to the console launching the executable'},
            {'value': 'remote_process_name', 'label': 'Remote Process Name', 'description': 'Name of the remote process to inject into', 'conditional': True},
        ]
    
    def get_input(self, obj):
        return {
            "github": fetch_exegol_executables()
        }
    
    def get_output(self, obj):
        return [
            {'name': 'file_extension', 'description': 'Output file format', 'default': '.exe'}
        ]


class DropperConfigSerializer(serializers.ModelSerializer):
    class Meta:
        model = DropperConfigModel
        fields = '__all__'

    def to_representation(self, instance):
        """Format the config data to match the frontend structure."""
        data = super().to_representation(instance)
        
        # Build features list
        features = {}
        for key in FEATURES_KEYS:
            features[key] = data.get(key, '')
        
        # Prepare the build_config structure
        build_config = {
            'id': data.get('id', ''),
            'is_template': data.get('is_template', False),
            'name': data.get('name', ''),
            'dropper_type': data.get('dropper_type', '').title(),
            'features': features,
            'options': {
                'debug_mode': data.get('debug_mode', False),
                'hide_console': data.get('hide_console', False),
                'redirect_output': data.get('redirect_output', False),
                'remote_process_name': data.get('remote_process_name', '')
            },
        }
        
        return build_config


class DropperSerializer(serializers.ModelSerializer):
    config = DropperConfigSerializer()
    architecture = serializers.CharField(write_only=True)
    entropy = serializers.FloatField(read_only=True)
    builder = serializers.CharField(read_only=True)
    
    class Meta:
        model = DropperModel
        fields = [
            'id', 'filename', 'size', 'architecture', 'entropy', 'md5_hash', 'sha256_hash', 'sha1_hash',
            'created_at', 'entropy', 'builder', 'config'
        ]
    
    def _get_enriched_data(self, obj):
        """Get and cache enriched data for the object with all required fields."""
        if not hasattr(self, '_enriched_data'):
            # Get base enriched data from the service
            enriched = DataEnrichmentService.enrich_dropper(obj).copy()
                
            # Set default values for required fields
            enriched.setdefault('size', '0 B')
            enriched.setdefault('entropy', 0.0)
            enriched.setdefault('type', 'Unknown')
            enriched.setdefault('architecture', 'Unknown')

            file_path = os.path.join(settings.MEDIA_ROOT, str(obj.file))

            # Add strings scan results if file exists
            if os.path.exists(file_path):
                try:
                    strings_engine = StringEngine()
                    strings_scan = strings_engine.scan_file(file_path)

                    # Add strings results to the dropper object
                    dropper_obj = DropperModel.objects.filter(id=obj.id).first()
                    dropper_obj.strings_results = strings_scan
                    dropper_obj.save()

                    enriched['strings_results'] = strings_scan.matches
                except Exception as e:
                    print(f"Error scanning file {file_path}: {e}")
                    enriched['strings_results'] = []
            elif obj.strings_results:
                enriched['strings_results'] = obj.strings_results.matches
            else:
                enriched['strings_results'] = []
            
            # Add YARA scan results if file exists
            if os.path.exists(file_path) and obj.yara_results is None:
                try:
                    yara_engine = YaraEngine()
                    yara_scan = yara_engine.scan_file(file_path)

                    # Add YARA results to the dropper object
                    dropper_obj = DropperModel.objects.filter(id=obj.id).first()
                    dropper_obj.yara_results = yara_scan
                    dropper_obj.save()

                    enriched['yara_results'] = yara_scan.matches
                except Exception as e:
                    print(f"Error scanning file {file_path}: {e}")
                    enriched['yara_results'] = []
            elif obj.yara_results:
                enriched['yara_results'] = obj.yara_results.matches
            else:
                enriched['yara_results'] = []

            # Add VirusTotal data
            if os.path.exists(file_path):
                vt_engine = VirusTotalEngine(file_hash=obj.md5_hash)
                vt_data = vt_engine.check_file()

                # Add VirusTotal results to the dropper object
                dropper_obj = DropperModel.objects.filter(id=obj.id).first()
                dropper_obj.virustotal_results = vt_data
                dropper_obj.save()

                enriched['virustotal_results'] = vt_data

            self._enriched_data = enriched
            
        return self._enriched_data
    
    def to_representation(self, instance):
        """Override the default representation to include additional fields."""
        # Get the base representation with model fields
        data = super().to_representation(instance)
        
        # Update with enriched data
        enriched_data = self._get_enriched_data(instance)
        data.update(enriched_data)
        
        # Add YARA results from enriched data
        data['yara_results'] = enriched_data.get('yara_results', [])
        
        # Add other empty placeholders for future implementation
        data.update({
            'strings': [],
            'virustotal': None,
            'edr_plugins': None
        })
        
        return data
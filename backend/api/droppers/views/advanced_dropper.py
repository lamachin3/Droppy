from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from ..models.dropper_config_model import DropperConfigModel
from ..services.github import fetch_exegol_executables
from drf_spectacular.utils import extend_schema


class AdvancedDropperView(APIView):

    permission_classes = [IsAuthenticated]

    @extend_schema(
        tags=['Dropper Builder'],
        summary='Get dropper configuration options',
        description='Returns all available options for the dropper configuration.',
    )
    def get(self, request, *args, **kwargs):
        """
        Return all available options for the dropper configuration.
        """
        data = {}
        data['features'] = [
            {'name': 'injector', 'required': True,'options': [
                {'value': value, 'label': label} 
                for value, label in DropperConfigModel.InjectorType.choices
            ]},
            {'name': 'loader', 'required': True,'options': [
                {'value': value, 'label': label}
                for value, label in DropperConfigModel.LoaderType.choices
            ]},
            {'name': 'obfuscation', 'options': [
                {'value': value, 'label': label}
                for value, label in DropperConfigModel.ObfuscationType.choices
                if value  # Exclude empty string
            ]},
            {'name': 'amsi_bypass', 'options': [
                {'value': value, 'label': label}
                for value, label in DropperConfigModel.AMSIBypass.choices
                if value  # Exclude empty string
            ]},
            {'name': 'etw_bypass', 'options': [
                {'value': value, 'label': label}
                for value, label in DropperConfigModel.ETWBypass.choices
                if value  # Exclude empty string
            ]},
            {'name': 'unhooking', 'options': [
                {'value': value, 'label': label}
                for value, label in DropperConfigModel.UnhookingType.choices
                if value  # Exclude empty string
            ]},
            {'name': 'syscalls', 'options': [
                {'value': value, 'label': label}
                for value, label in DropperConfigModel.SyscallsType.choices
                if value  # Exclude empty string
            ]},
        ]

        data['input'] = {
            "github": fetch_exegol_executables()
        }

        data['options'] = [
            {'value': 'debug_mode', 'label': 'Enable Debug Mode'},
            {'value': 'hide_console', 'label': 'Hide Console'},
            {'value': 'redirect_output', 'label': 'Redirect Output to Current Console'},
            {'value': 'remote_process_name', 'label': 'Remote Process Name', 'conditional': True},
            #{'value': 'binary_signing', 'label': 'Binary Signing'},
        ]

        data['output'] = [
            {'name': 'file_extension', 'label': 'File Extension', 'options': [
                {'value': '.exe', 'label': 'Windows Executable (.exe)'}
            ]}
        ]

        return Response(data, status=200)

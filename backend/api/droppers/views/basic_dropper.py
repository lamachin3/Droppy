from django.conf import settings
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework import status
from drf_spectacular.utils import extend_schema, OpenApiResponse, OpenApiExample
from ..serializers.dropper_serializer import (
    BasicDropperRequestSerializer,
    BasicDropperResponseSerializer
)
from ..serializers.compilation_serializer import CompileDropperSerializer
from ..services.compilation import compile_dropper_task, DropperBuilder
from ..models.dropper_config_model import DropperConfigModel

class BasicDropperView(APIView):
    """
    A simplified view for dropper configuration that provides a basic interface
    with predefined options for each feature.
    """
    permission_classes = [IsAuthenticated]

    # Predefined options for basic mode
    BASIC_OPTIONS = {
        'local_injection': DropperConfigModel.InjectorType.APC_INJECTION,
        'remote_injection': DropperConfigModel.InjectorType.EARLY_CASCADE_INJECTION,
        'loader': DropperConfigModel.LoaderType.FILE_MAPPING,
        'obfuscation': DropperConfigModel.ObfuscationType.IPV6_OBFUSCATION,
        'amsi_bypass': DropperConfigModel.AMSIBypass.JNE_BASED_AMSI_PATCH,
        'etw_bypass': DropperConfigModel.ETWBypass.JMP_RET_BASED_ETW_PATCH,
        'unhooking': DropperConfigModel.UnhookingType.KNOWN_DLLS_UNHOOKING,
        'syscalls': DropperConfigModel.SyscallsType.HW_SYSCALLS,
    }
    
    def get_serializer_context(self):
        """Extra context provided to the serializer class."""
        return {
            'request': self.request,
            'format': self.format_kwarg,
            'view': self
        }

    @extend_schema(
        tags=['Basic Dropper Builder'],
        summary='Get basic dropper configuration options',
        description='Returns available features for basic dropper configuration without detailed options.',
        responses={
            200: BasicDropperResponseSerializer,
        }
    )
    def get(self, request, *args, **kwargs):
        """
        Return available features for basic dropper configuration.
        Only returns feature names and whether they're required, not the detailed options.
        """
        serializer = BasicDropperResponseSerializer(data={}, context=self.get_serializer_context())
        serializer.is_valid(raise_exception=True)

        for key, value in self.BASIC_OPTIONS.items():
            features = serializer.data['features']
            for feature in features:
                if feature['name'] == key:
                    feature['description'] = f"{feature['description']} ({value.label})"

        return Response(serializer.data, status=200)

    @extend_schema(
        tags=['Basic Dropper Builder'],
        summary='Build a basic dropper',
        description='Builds a dropper with simplified configuration using predefined options.',
        request=BasicDropperRequestSerializer,
        responses={
            202: OpenApiResponse(
                description='Dropper compilation started',
                examples=[
                    OpenApiExample(
                        'Success Response',
                        value={'task_id': '550e8400-e29b-41d4-a716-446655440000'}
                    )
                ]
            ),
            400: OpenApiResponse(
                description='Invalid dropper configuration',
                examples=[
                    OpenApiExample(
                        'Error Response',
                        value={'detail': 'Invalid dropper configuration'}
                    )
                ]
            )
        }
    )
    def post(self, request, *args, **kwargs):
        """
        Build a dropper with simplified configuration.
        Users only need to specify which features they want to enable,
        and the backend will use predefined optimal options.
        """
        # Validate the request data first
        basic_serializer = BasicDropperRequestSerializer(
            data=request.data,
            context=self.get_serializer_context()
        )
        basic_serializer.is_valid(raise_exception=True)
        
        # Start with default values
        config = self.BASIC_OPTIONS.copy()
        
        # Update with user's feature selections
        for feature in basic_serializer.validated_data:
            if feature in self.BASIC_OPTIONS.keys():
                value = basic_serializer.validated_data[feature]
                if value:
                    config[feature] = self.BASIC_OPTIONS[feature].value
                else:
                    config[feature] = ""
            else:
                config[feature] = basic_serializer.validated_data[feature]
        config['injector'] = config['local_injection'] or config['remote_injection']
        
        # Validate the final configuration with the compilation serializer
        compile_serializer = CompileDropperSerializer(data=config)
        if not compile_serializer.is_valid():
            return Response(compile_serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            
        if settings.ASYNC_BUILD:
            task = compile_dropper_task.delay(compile_serializer.validated_data, type="basic")
            return Response(
                {'task_id': task.id},
                status=status.HTTP_202_ACCEPTED
            )
        else:
            dropper = DropperBuilder(compile_serializer.validated_data, dropper_type="basic").build()
            response = {
                'success': True,
                'file_url': f"/file-details/{dropper.id}",
            }
            return Response(response, status=status.HTTP_200_OK)
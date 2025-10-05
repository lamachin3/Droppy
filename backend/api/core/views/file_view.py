import os
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from django.http import FileResponse, Http404
from django.core.exceptions import ObjectDoesNotExist
from drf_spectacular.utils import extend_schema, OpenApiResponse, OpenApiExample, OpenApiParameter

from ..services.file_manager import FileManager
from api.core.models.file_model import FileModel
from api.core.serializers.file_serializer import FileModelDetailsSerializer, FileModelSerializer
from api.droppers.models.dropper_model import DropperModel
from api.droppers.serializers.dropper_serializer import DropperSerializer



class FileViewSet(viewsets.ModelViewSet):
    queryset = FileModel.objects.all()
    serializer_class = FileModelSerializer
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.file_manager = FileManager()

    @extend_schema(
        tags=['Builds'],
        summary='List available builds',
        description='Returns a list of all available builds.',
        responses={
            200: OpenApiResponse(
                description='List of available builds',
                examples=[
                    OpenApiExample(
                        'Success Response',
                        value={
                            'builds': [
                                {
                                    'id': 'dropper.exe',
                                    'name': 'dropper.exe', 
                                    'size': 1024, 
                                    'created_at': 1694000000,
                                    'download_url': 'http://example.com/api/builds/dropper.exe/download/'
                                }
                            ]
                        }
                    )
                ]
            )
        }
    )
    def list(self, request):
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True, context={'request': request})
        return Response({
            'count': len(serializer.data),
            'results': serializer.data
        }, status=status.HTTP_200_OK)

    @extend_schema(
        tags=['Builds'],
        summary='Get build details',
        description='Retrieves detailed information about a specific build.',
        parameters=[
            OpenApiParameter(
                name='pk',
                type=str,
                location=OpenApiParameter.PATH,
                description='Name/ID of the build to retrieve',
                required=True
            )
        ],
        responses={
            200: OpenApiResponse(
                description='Build details',
                examples=[
                    OpenApiExample(
                        'Success Response',
                        value={
                            'id': 'dropper.exe',
                            'name': 'dropper.exe',
                            'build_type': 'dropper',
                            'size': 1024,
                            'created_at': '2023-09-06T12:00:00Z',
                            'metadata': {
                                'version': '1.0.0',
                                'platform': 'windows'
                            },
                            'download_url': 'http://example.com/api/builds/dropper.exe/download/'
                        }
                    )
                ]
            ),
            404: OpenApiResponse(description='Build not found')
        }
    )
    def retrieve(self, request, pk=None):
        build = FileModel.objects.filter(id=pk).first() or FileModel.objects.filter(name=pk).first()
        if not build:
            raise Http404("Build not found")
        
        if isinstance(build, DropperModel):
            serializer_class = DropperSerializer
        else:
            serializer_class = FileModelSerializer

        serializer = serializer_class(build)
        build_data = serializer.data

        return Response(build_data, status=status.HTTP_200_OK)


    @extend_schema(
        tags=['Builds'],
        summary='Download a build',
        description='Downloads a specific build by filename.',
        parameters=[
            OpenApiParameter(
                name='pk',
                type=str,
                location=OpenApiParameter.PATH,
                description='Name/ID of the build to download',
                required=True
            )
        ],
        responses={
            200: OpenApiResponse(description='File download'),
            404: OpenApiResponse(description='Build not found')
        }
    )
    @action(detail=True, methods=['get'], url_path='download', url_name='download')
    def download(self, request, pk=None, *args, **kwargs):
        build = self.file_manager.get_build(pk)
        if not build:            
            raise Http404("Build not found")
        
        build_path = self.file_manager.get_build_path(build.name)
        response = FileResponse(open(build_path, 'rb'), content_type='application/octet-stream')
        response['Content-Disposition'] = f'attachment; filename="{build.name}"'
        return response
        
    @extend_schema(
        tags=['Builds'],
        summary='Delete a build',
        description='Deletes a specific build by filename or ID.',
        parameters=[
            OpenApiParameter(
                name='pk',
                type=str,
                location=OpenApiParameter.PATH,
                description='Name/ID of the build to delete',
                required=True
            )
        ],
        responses={
            204: OpenApiResponse(description='Build deleted successfully'),
            404: OpenApiResponse(description='Build not found'),
            500: OpenApiResponse(description='Error deleting build')
        }
    )
    def destroy(self, request, pk=None, *args, **kwargs):
        try:
            try:
                file_obj = FileModel.objects.filter(id=pk).first()
            except FileModel.DoesNotExist:
                return Response(
                    {'detail': f'Build with ID "{pk}" not found'},
                    status=status.HTTP_404_NOT_FOUND
                )

            file_obj.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)
                
        except Exception as e:
            print(e)
            return Response(
                {'detail': f'Error deleting build: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

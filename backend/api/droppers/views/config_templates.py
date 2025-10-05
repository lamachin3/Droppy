import json
from rest_framework import viewsets, permissions, status
from rest_framework.decorators import action
from rest_framework.response import Response
from django.http import HttpResponse
from ..models.dropper_config_model import DropperConfigModel
from ..serializers.dropper_serializer import DropperConfigSerializer


class DropperConfigTemplateViewSet(viewsets.ModelViewSet):
    """
    API endpoint for managing dropper configuration templates.
    Returns all configurations with template toggle functionality.
    """
    serializer_class = DropperConfigSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        """Return configurations created by the current user."""
        return DropperConfigModel.objects.filter(is_template=True)

    def list(self, request, *args, **kwargs):
        if 'dropper_type' in request.query_params:
            dropper_type = request.query_params['dropper_type']
            data = DropperConfigModel.objects.filter(is_template=True, dropper_type=dropper_type)
            return Response(DropperConfigSerializer(data, many=True).data)
        
        return super().list(request, *args, **kwargs)

    def create(self, request, *args, **kwargs):
        file_obj = request.FILES.get('file', None)
        data = None

        if file_obj:
            try:
                file_data = file_obj.read().decode('utf-8')
                data = json.loads(file_data)
            except json.JSONDecodeError:
                return Response(
                    {"error": "Uploaded file is not valid JSON."},
                    status=status.HTTP_400_BAD_REQUEST
                )
        else:
            data = request.data

        print(data)
        serializer = self.get_serializer(data=data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)

        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)

    @action(detail=True, methods=['post'])
    def toggle(self, request, pk=None):
        config = DropperConfigModel.objects.get(pk=pk)
        config.is_template = not config.is_template
        config.save()
        return Response({"is_template": config.is_template}, status=status.HTTP_200_OK)

    @action(detail=True, methods=['post'])
    def rename(self, request, pk=None):
        config = DropperConfigModel.objects.get(pk=pk)
        config.name = request.data['name']
        config.save()
        return Response({"name": config.name}, status=status.HTTP_200_OK)

    @action(detail=True, methods=['get'])
    def download(self, request, pk=None):
        config = self.get_object()
        serializer = self.get_serializer(config)
        data = serializer.data

        data.pop('id')
        json_content = json.dumps(data, indent=4)

        safe_name = "".join(c if c.isalnum() or c in ('-', '_') else '_' for c in config.name)
        filename = f"{safe_name}.json"

        response = HttpResponse(json_content, content_type='application/json')
        response['Content-Disposition'] = f'attachment; filename="{filename}"'

        return response

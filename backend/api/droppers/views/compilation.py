from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from api.droppers.services.compilation import compile_dropper_task, DropperBuilder
from django.conf import settings
from drf_spectacular.utils import extend_schema, OpenApiResponse, OpenApiExample
from api.droppers.serializers.compilation_serializer import CompileDropperSerializer
from api.droppers.services.shellcode.shellcode_convertor import file_to_shellcode

class CompileDropperView(APIView):

    permission_classes = [IsAuthenticated]

    @extend_schema(
        tags=['Dropper Builder'],
        summary='Compile a dropper',
        description='Compiles a dropper with the given configuration.',
        request=CompileDropperSerializer,
        responses={
            202: OpenApiResponse(
                description='Dropper compilation accepted',
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
    def post(self, request):
        # Create a mutable copy of the request data
        data = request.data.copy()

        serializer = CompileDropperSerializer(data=data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            
        if settings.ASYNC_BUILD:
            task = compile_dropper_task.delay(serializer.validated_data, type="advanced")
            return Response(
                {'task_id': task.id},
                status=status.HTTP_202_ACCEPTED
            )
        else:
            dropper = DropperBuilder(serializer.validated_data, dropper_type="advanced").build()
            response = {
                'success': True,
                'file_url': f"/file-details/{dropper.id}",
            }
            return Response(response, status=status.HTTP_200_OK)

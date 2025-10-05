from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from ..serializers import UserSerializer, RegisterSerializer
from drf_spectacular.utils import extend_schema, OpenApiExample, OpenApiResponse, OpenApiTypes, extend_schema_view
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.openapi import AutoSchema
from django.utils.translation import gettext_lazy as _


@extend_schema(
    tags=['Users'],
    summary='User Profile',
    description='Get or update the authenticated user\'s profile information.'
)
class UserProfileView(APIView):
    permission_classes = [IsAuthenticated]
    
    @extend_schema(
        operation_id='get_user_profile',
        summary='Get user profile',
        description='Retrieve the authenticated user\'s profile information.',
        responses={
            200: UserSerializer,
            401: OpenApiResponse(
                description='User not authenticated',
                examples=[
                    OpenApiExample(
                        'Error Response',
                        value={'detail': 'Authentication credentials were not provided.'}
                    )
                ]
            )
        }
    )
    def get(self, request):
        serializer = UserSerializer(request.user)
        return Response(serializer.data)
    
    @extend_schema(
        operation_id='update_user_profile',
        summary='Update user profile',
        description='Update the authenticated user\'s profile information.',
        request=UserSerializer,
        responses={
            200: UserSerializer,
            400: OpenApiResponse(
                description='Invalid input data',
                examples=[
                    OpenApiExample(
                        'Error Response',
                        value={
                            'email': ['This field is required.'],
                            'firstname': ['This field is required.']
                        }
                    )
                ]
            ),
            401: OpenApiResponse(
                description='User not authenticated',
                examples=[
                    OpenApiExample(
                        'Error Response',
                        value={'detail': 'Authentication credentials were not provided.'}
                    )
                ]
            )
        }
    )
    def put(self, request):
        serializer = UserSerializer(request.user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@extend_schema(
    tags=['Authentication'],
    summary='Register a new user',
    description='Creates a new user account with the provided details.',
    request=RegisterSerializer,
    responses={
        201: OpenApiResponse(
            response=UserSerializer,
            description='User registered successfully',
            examples=[
                OpenApiExample(
                    'Success Response',
                    value={
                        'user': {
                            'id': '550e8400-e29b-41d4-a716-446655440000',
                            'email': 'user@example.com',
                            'firstname': 'John',
                            'lastname': 'Doe'
                        }
                    }
                )
            ]
        ),
        400: OpenApiResponse(
            response=OpenApiTypes.OBJECT,
            description='Invalid input data',
            examples=[
                OpenApiExample(
                    'Error Response',
                    value={
                        'email': ['This field is required.'],
                        'password': ['This field is required.']
                    }
                )
            ]
        )
    }
)
class RegisterView(APIView):
    permission_classes = [AllowAny]
    
    @extend_schema(
        operation_id='register_user',
        summary='Register a new user',
        description='Create a new user account with the provided details.'
    )
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            return Response({
                'user': UserSerializer(user).data
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

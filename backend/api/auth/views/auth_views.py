from rest_framework.views import APIView
from rest_framework import status
from rest_framework.response import Response
from rest_framework import status, permissions
from rest_framework.response import Response
from rest_framework.views import APIView
from drf_spectacular.utils import extend_schema, OpenApiResponse, OpenApiExample, OpenApiTypes
from django.contrib.auth import login as auth_login, logout as auth_logout
from django.contrib.auth.hashers import check_password

from api.auth.serializers import LoginSerializer
from api.users.serializers import UserSerializer, RegisterSerializer
from rest_framework.throttling import AnonRateThrottle
from django.middleware.csrf import get_token
from django.conf import settings


@extend_schema(
    tags=['Authentication'],
    summary='Login user',
    description='Authenticate a user and return an access token.',
    request=LoginSerializer,
    responses={
        200: OpenApiResponse(
            response=OpenApiTypes.OBJECT,
            description='Authentication successful',
            examples=[
                OpenApiExample(
                    'Success Response',
                    value={
                        'user': {
                            'id': '550e8400-e29b-41d4-a716-446655440000',
                            'email': 'user@example.com',
                            'firstname': 'John',
                            'lastname': 'Doe'
                        },
                        'message': 'Login successful',
                        'sessionid': 'session_key'
                    }
                )
            ]
        ),
        400: OpenApiResponse(
            response=OpenApiTypes.OBJECT,
            description='Invalid credentials',
            examples=[
                OpenApiExample(
                    'Error Response',
                    value={
                        'error': 'Unable to log in with provided credentials.'
                    }
                )
            ]
        )
    }
)
class LoginView(APIView):
    """
    View to handle user login using Django's session authentication.
    """
    permission_classes = [permissions.AllowAny]
    throttle_classes = [AnonRateThrottle]
    
    @extend_schema(
        tags=['Authentication'],
        summary='Login user',
        description='Authenticate user using session-based authentication.'
    )
    def post(self, request):
        serializer = LoginSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            user = serializer.validated_data['user']
            auth_login(request, user)
            return Response({
                'user': UserSerializer(user).data,
                'message': 'Login successful',
                'sessionid': request.session.session_key
            })
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@extend_schema(
    tags=['Authentication'],
    summary='Check authentication status',
    description='Check if user is authenticated using session and return user data.',
    responses={
        200: OpenApiResponse(
            response=OpenApiTypes.OBJECT,
            description='User is authenticated',
            examples=[
                OpenApiExample(
                    'Success Response',
                    value={
                        'isAuthenticated': True,
                        'user': {
                            'id': '550e8400-e29b-41d4-a716-446655440000',
                            'email': 'user@example.com',
                            'firstname': 'John',
                            'lastname': 'Doe'
                        },
                        'sessionid': 'session_key'
                    }
                )
            ]
        ),
        401: OpenApiResponse(
            response=OpenApiTypes.OBJECT,
            description='User is not authenticated',
            examples=[
                OpenApiExample(
                    'Error Response',
                    value={
                        'isAuthenticated': False
                    }
                )
            ]
        )
    }
)
class CheckAuthView(APIView):
    """
    View to check if user is authenticated and return user data.
    Uses Django's session-based authentication.
    """
    permission_classes = [permissions.IsAuthenticated]
    
    @extend_schema(
        tags=['Authentication'],
        summary='Check authentication status',
        description='Check if user is authenticated using session and return user data.'
    )
    def get(self, request):
        if request.user.is_authenticated:
            return Response({
                'isAuthenticated': True,
                'user': UserSerializer(request.user).data,
                'sessionid': request.session.session_key
            })
        return Response(
            {'isAuthenticated': False}, 
            status=status.HTTP_401_UNAUTHORIZED
        )

@extend_schema(
    tags=['Authentication'],
    summary='Logout user',
    description='Invalidate the current user\'s authentication token.',
    responses={
        200: OpenApiResponse(
            description='Successfully logged out',
            examples=[
                OpenApiExample(
                    'Success Response',
                    value={'detail': 'Successfully logged out.'}
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
class LogoutView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    
    @extend_schema(
        operation_id='logout_user',
        summary='Logout user',
        description='Invalidate the current user\'s authentication token.'
    )
    def post(self, request):
        auth_logout(request)
        return Response(status=status.HTTP_200_OK)

class CSRFView(APIView):
    permission_classes = [permissions.AllowAny]
    
    @extend_schema(
        operation_id='get_csrf_token',
        summary='Get CSRF token',
        description='Retrieve a CSRF token for use in subsequent authenticated requests.',
        responses={
            200: OpenApiResponse(
                description='CSRF token generated successfully',
                examples=[
                    OpenApiExample(
                        'Success Response',
                        value={'csrf_token': 'abc123...'}
                    )
                ]
            )
        }
    )
    def get(self, request):
        # Ensure a CSRF token is set in the session
        csrf_token = get_token(request)
        
        response = Response({
            'csrf_token': csrf_token
        })
        
        # Set the CSRF token in a cookie for browser-based clients
        response.set_cookie(
            'csrftoken',
            csrf_token,
            max_age=60 * 60 * 24 * 7,  # 1 week
            httponly=True,
            samesite='Lax',
            secure=not settings.DEBUG  # Only send over HTTPS in production
        )
        
        return response

from rest_framework import serializers
from django.contrib.auth import authenticate
from django.contrib.auth import get_user_model
from django.utils.translation import gettext_lazy as _
from drf_spectacular.utils import extend_schema_serializer, OpenApiExample

User = get_user_model()


@extend_schema_serializer(
    examples=[
        OpenApiExample(
            'Login Request Example',
            value={
                'email': 'user@example.com',
                'password': 'securepassword123'
            },
            request_only=True,
            status_codes=['200']
        ),
        OpenApiExample(
            'Login Response Example',
            value={
                'user': {
                    'id': '550e8400-e29b-41d4-a716-446655440000',
                    'email': 'user@example.com',
                    'firstname': 'John',
                    'lastname': 'Doe'
                },
                'message': 'Login successful',
                'sessionid': 'session_key_here'
            },
            response_only=True,
            status_codes=['200']
        )
    ]
)
class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField(
        required=True,
        help_text='Email address of the user.'
    )
    password = serializers.CharField(
        style={'input_type': 'password'}, 
        write_only=True,
        help_text='User password.'
    )

    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')
        request = self.context.get('request')

        if not all([email, password]):
            raise serializers.ValidationError(
                'Must include "email" and "password".',
                code='authorization'
            )

        # Try to authenticate the user
        user = authenticate(
            request=request,
            email=email,
            password=password
        )

        if not user:
            raise serializers.ValidationError(
                'Unable to log in with provided credentials.',
                code='authorization'
            )

        if not user.is_active:
            raise serializers.ValidationError(
                'This account is inactive.',
                code='inactive_account'
            )

        attrs['user'] = user
        return attrs

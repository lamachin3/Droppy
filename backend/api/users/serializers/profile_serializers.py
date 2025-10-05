from rest_framework import serializers
from ..models.user_model import User
from django.utils.translation import gettext_lazy as _
from drf_spectacular.utils import extend_schema_serializer, OpenApiExample


@extend_schema_serializer(
    examples=[
        OpenApiExample(
            'User Response Example',
            value={
                'id': '550e8400-e29b-41d4-a716-446655440000',
                'email': 'user@example.com',
                'firstname': 'John',
                'lastname': 'Doe',
                'is_staff': False,
                'is_manager': False,
                'is_verified': True,
                'last_login': '2023-01-01T12:00:00Z'
            },
            response_only=True,
            status_codes=['200']
        )
    ]
)
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'email', 'username', 'firstname', 'lastname', 'is_staff', 'is_manager', 'is_verified', 'last_login')
        read_only_fields = ('id', 'is_staff', 'is_manager', 'is_verified', 'last_login')

@extend_schema_serializer(
    examples=[
        OpenApiExample(
            'Register Request Example',
            value={
                'email': 'user@example.com',
                'username': 'john_doe',
                'firstname': 'John',
                'lastname': 'Doe',
                'password': 'securepassword123',
                'password2': 'securepassword123'
            },
            request_only=True,
            status_codes=['201']
        )
    ]
)
class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        write_only=True, 
        required=True, 
        style={'input_type': 'password'},
        help_text='Password for the new account.'
    )
    password2 = serializers.CharField(
        write_only=True, 
        required=True, 
        style={'input_type': 'password'},
        help_text='Confirm the password.'
    )

    class Meta:
        model = User
        fields = ('email', 'username', 'firstname', 'lastname', 'password', 'password2')
        extra_kwargs = {
            'firstname': {'required': False},
            'lastname': {'required': False}
        }

    def validate(self, attrs):
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError({"password": "Password fields didn't match."})
        return attrs

    def create(self, validated_data):
        validated_data.pop('password2', None)
        user = User.objects.create_user(
            email=validated_data.get('email'),
            username=validated_data.get('username'),
            firstname=validated_data.get('firstname', ''),
            lastname=validated_data.get('lastname', ''),
            password=validated_data.get('password')
        )
        return user

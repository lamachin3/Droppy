import uuid
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models
from django.utils.translation import gettext_lazy as _


class UserManager(BaseUserManager):
    use_in_migrations = True

    def _create_user(self, email, password, is_staff, is_superuser,
                     **extra_fields):
        if not email:
            raise ValueError('The given email must be set')
        email = self.normalize_email(email)
        user = self.model(email=email,
                          is_staff=is_staff,
                          is_superuser=is_superuser,
                          **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, email=None, password=None, **extra_fields):
        return self._create_user(email,
                                 password,
                                 is_staff=False,
                                 is_superuser=False,
                                 **extra_fields)

    def create_superuser(self, email, password, **extra_fields):
        return self._create_user(email,
                                 password,
                                 is_staff=True,
                                 is_superuser=True,
                                 **extra_fields)

class User(AbstractBaseUser, PermissionsMixin):
    objects = UserManager()

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    is_staff = models.BooleanField(_('staff status'), default=False)
    is_manager = models.BooleanField(default=False)
    is_verified = models.BooleanField(default=False)

    username = models.CharField(max_length=255, unique=True)
    firstname = models.CharField(max_length=255, blank=True, null=True)
    lastname = models.CharField(max_length=255, blank=True, null=True)
    email = models.EmailField(max_length=255, unique=True)
    locked = models.BooleanField(default=False)

    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.CharField(max_length=255, null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)
    updated_by = models.CharField(max_length=255, null=True, blank=True)
    last_login = models.DateTimeField(_('last login'), auto_now=True, blank=True, null=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []
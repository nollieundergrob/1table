from .serializers import *
from .models import *

from django.contrib.auth import authenticate
from django.contrib.auth.hashers import make_password,check_password
from django.conf import settings
from django.shortcuts import get_object_or_404, render

from rest_framework.viewsets import ModelViewSet
from rest_framework.permissions import IsAuthenticated
from rest_framework.authtoken.models import Token
from rest_framework.generics import ListCreateAPIView, RetrieveUpdateDestroyAPIView
from rest_framework.mixins import *
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.views import TokenObtainPairView





DEBUG = settings.DEBUG

class EmailTokenObtainPairView(TokenObtainPairView):
    """
    Авторизация через email и пароль. Возвращает JWT-токен.

    Методы:
    - **POST**: Аутентифицирует пользователя и возвращает токен доступа (access) и обновления (refresh).
    """
    serializer_class = CustomTokenObtainPairSerializer



class UserListCreateAPIView(ListCreateAPIView):
    """
    Список пользователей и создание нового пользователя.

    Методы:
    - **GET**: Возвращает список всех пользователей.
    - **POST**: Создаёт нового пользователя.
    """
    serializer_class = UserSerializer
    queryset = User.objects.all()

    def get(self, request, *args, **kwargs):
        """
        Переопределяем метод для авторизации через параметры запроса.
        """
        auth = self.request.query_params.get('auth', None)
        if auth:
            username = self.request.query_params.get('username', None)
            password = self.request.query_params.get('password', None)

            if username and password:
                user = authenticate(username=username, password=password)
                if user:
                    response = {
                        'detail': 'Successful authorization',
                        'auth': True
                    }
                    if DEBUG:
                        response.update({'password': user.password})
                    return Response(response)
                else:
                    return Response({
                        'detail': 'No such user with this username and password.',
                        'auth': False
                    }, status=status.HTTP_404_NOT_FOUND)
            else:
                return Response({
                    'detail': 'username and password are required.',
                    'auth': False
                }, status=status.HTTP_400_BAD_REQUEST)

        return super().get(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        """
        Создание нового пользователя.
        """
        return super().post(request, *args, **kwargs)


class UserRetrieveUpdateDestroyAPIView(RetrieveUpdateDestroyAPIView):
    """
    Получение, обновление и удаление пользователя.

    Методы:
    - **GET**: Получить информацию о конкретном пользователе.
    - **PATCH**: Частично обновить данные пользователя.
    - **PUT**: Полностью обновить данные пользователя.
    - **DELETE**: Удалить пользователя (защищено для staff-пользователей).
    """
    serializer_class = UserSerializer
    queryset = User.objects.all()
    lookup_field = 'pk'

    def patch(self, request, *args, **kwargs):
        """
        Частичное обновление пользователя.
        """
        return super().partial_update(request, *args, **kwargs)

    def put(self, request, *args, **kwargs):
        """
        Полное обновление данных пользователя.
        """
        return super().update(request, *args, **kwargs)

    def delete(self, request, *args, **kwargs):
        """
        Удаление пользователя.
        Проверяем, чтобы нельзя было удалить пользователя с флагом is_staff.
        """
        user = self.get_object()
        if user.is_staff:
            return Response({'detail': 'Forbidden: Cannot delete staff users.'},
                            status=status.HTTP_403_FORBIDDEN)
        user.delete()
        return Response({'detail': 'User deleted successfully.'}, status=status.HTTP_204_NO_CONTENT)



class AvatarViewSet(ModelViewSet):
    """
    Управление аватарками пользователя.

    Методы:
    - **GET**: Получение списка аватарок текущего пользователя.
    - **POST**: Создание новой аватарки.
    - **PUT**: Полное обновление аватарки.
    - **PATCH**: Частичное обновление аватарки.
    - **DELETE**: Удаление аватарки.
    """
    
    serializer_class = AvatarSerializer
    permission_classes = [IsAuthenticated]  # Только для аутентифицированных пользователей

    def get_queryset(self):
        """
        Возвращает аватарки только текущего пользователя.
        """
        print(f"Authenticated user: {self.request.user}, ID: {self.request.user.id}")
        
        return UserAvatar.objects.filter(user=self.request.user.id)

    def perform_create(self, serializer):
        """
        Устанавливаем текущего пользователя при создании аватарки.
        """
        serializer.save(user=self.request.user)


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    """
    Авторизация через email и пароль. Возвращает JWT-токен.

    Методы:
    - **POST**: Аутентифицирует пользователя и возвращает токен доступа (access) и обновления (refresh).
    """
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)

        # Добавляем кастомные данные в токен (например, email)
        token['email'] = user.email
        return token

    def validate(self, attrs):
        # Используем email вместо username
        credentials = {
            'email': attrs.get('email'),
            'password': attrs.get('password'),
        }
        user = authenticate(**credentials)

        if user and user.is_active:
            return super().validate(attrs)
        raise serializers.ValidationError({'detail': 'Invalid email or password'})

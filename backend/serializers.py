from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

from .models import *

from django.contrib.auth import authenticate


class AvatarSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserAvatar
        fields = ('avatar_url',)


class UserSerializer(serializers.ModelSerializer):
    avatar_urls = serializers.SerializerMethodField()

    def get_avatar_urls(self, obj):
        last_avatar = obj.avatar.last()
        if last_avatar:
            return AvatarSerializer(last_avatar).data
        return None 

    class Meta:
        model = User
        fields = ('id', 'username', 'password', 'online', 'email', 'avatar_urls')



class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
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
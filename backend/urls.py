from django.urls import path,include

from .views import *

from rest_framework.routers import DefaultRouter

from rest_framework_simplejwt.views import TokenRefreshView



router = DefaultRouter()
router.register(r'avatars',AvatarViewSet,basename='avatars')

# User
user_urls = [
    path('users', UserListCreateAPIView.as_view(), name='user-list-create'),
    path('users/<int:pk>', UserRetrieveUpdateDestroyAPIView.as_view(), name='user-detail'),]

auth_urls = [
    path('auth/token/', EmailTokenObtainPairView.as_view(), name='token_obtain_pair'),  # Получение токена
    path('auth/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),     # Обновление токена
]






urlpatterns = [

    ]+user_urls+auth_urls

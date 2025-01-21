from django.urls import path
from .views import *

urlpatterns = [
    path('users',view=UserAPIView.as_view(),name='user_model')
]

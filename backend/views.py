from django.shortcuts import get_object_or_404, render
from .serializers import *
from .models import *
from rest_framework.generics import ListCreateAPIView
from rest_framework.mixins import *
from rest_framework.response import Response
# Create your views here.



class UserAPIView(ListCreateAPIView,UpdateModelMixin):
    serializer_class = UserSerializer
    def get(self, request, *args, **kwargs):
        queryset = User.objects.all()
        id = self.request.query_params.get('id',None)
        
        
        if id:
            queryset =queryset.filter(id=id)
        serializer = self.serializer_class(queryset, many=True)
        return Response(serializer.data)
        
    def get_queryset(self):
        return self.queryset
    
    def post(self, request, *args, **kwargs):
        return super().create(request, *args, **kwargs)
    
    
    def patch(self, request, *args, **kwargs):
        user_id = request.query_params.get('id')
        user = get_object_or_404(self.queryset, id=user_id)
        serializer = self.serializer_class(user, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)

    def put(self, request, *args, **kwargs):
        user_id = request.query_params.get('id')
        user = get_object_or_404(self.queryset, id=user_id)
        serializer = self.serializer_class(user, data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)

    def delete(self, request, *args, **kwargs):
        user_id = request.query_params.get('id')
        user = get_object_or_404(self.queryset, id=user_id)
        user.delete()
        return Response({"detail": "User deleted successfully"}, status=status.HTTP_204_NO_CONTENT)
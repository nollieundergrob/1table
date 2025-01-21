from django.db import models
from django.contrib.auth.hashers import make_password
# Create your models here.

# #{"username":"",
# "password",
# "online":False,
# "email":"asd@mail.ru",
# 'id":1}


class User(models.Model):
    username = models.CharField(max_length=60)
    password = models.CharField(max_length=50)
    online = models.BooleanField("Статус онлайна")
    email = models.EmailField(verbose_name="Email", max_length=254)
    
    def save(self,*args, **kwargs):
        self.password = make_password(self.password)
        super().save(*args, **kwargs)
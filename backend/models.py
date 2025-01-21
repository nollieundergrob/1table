from django.db import models
from django.contrib.auth.hashers import make_password
from django.contrib.auth.models import AbstractUser
from django.db import models

class User(AbstractUser):
    username = models.CharField(max_length=60, unique=True)
    password = models.CharField(max_length=128)  # Увеличьте длину для хэша
    online = models.BooleanField("Статус онлайна", default=False)
    email = models.EmailField(verbose_name="Email", max_length=254, unique=True)

    def save(self, *args, **kwargs):
        self.password = make_password(self.password)
        super().save(*args, **kwargs)

    def __str__(self):
        return self.username
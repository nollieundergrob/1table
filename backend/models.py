from django.db import models
from django.contrib.auth.hashers import make_password
from django.contrib.auth.models import AbstractUser
from django.db import models

class User(AbstractUser):
    email = models.EmailField(unique=True)  # Уникальное поле email
    online = models.BooleanField("Статус онлайна", default=False, blank=True, null=True)

    USERNAME_FIELD = 'email'  # Используем email вместо username
    REQUIRED_FIELDS = ['username']  # Поля, которые обязательно должны быть заполнены


    def save(self, *args, **kwargs):
        if self.pk is None or self.has_changed_password():
            self.password = make_password(self.password)
        super().save(*args, **kwargs)

    def has_changed_password(self):
        try:
            original_user = User.objects.get(pk=self.pk)
            return original_user.password != self.password
        except User.DoesNotExist:
            return True

    def __str__(self):
        return self.username
    
    
class UserAvatar(models.Model):
    user = models.ForeignKey(to=User,on_delete=models.CASCADE,related_name='avatar')
    avatar_url = models.CharField(max_length=512)
    date = models.DateTimeField(auto_now=True)

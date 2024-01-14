from django.db import models
import datetime

# Create your models here.
class PasswordResetProfile(models.Model):
    id = models.AutoField(primary_key=True)
    username = models.TextField(default="No username found")
    last_token = models.TextField(default="No token found")
    date = models.DateTimeField(default=datetime.datetime.now())

    def __str__(self):
        return str(self.id)
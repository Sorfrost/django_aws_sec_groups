from django.db import models
from django.utils import timezone
from django.contrib.auth import get_user_model

# Create your models here.

class AwsKey(models.Model):
    key_id = models.CharField(primary_key=True, max_length=200)
    key_secret = models.CharField(max_length=200)
    region = models.CharField(max_length=50)
    comment = models.CharField(max_length=100, unique=True)
    active = models.BooleanField(default=False)
    last_used = models.DateTimeField(default=timezone.now())

    def __str__(self):
        return self.comment

class SecGroup(models.Model):
    GroupId = models.CharField(primary_key=True, max_length=200)
    GroupName = models.CharField(max_length=200)
    Description = models.CharField(max_length=200)

    def __str__(self):
        return self.GroupName

class SecGroupPermission(models.Model):
    username = models.ForeignKey(get_user_model(), on_delete=models.CASCADE)
    GroupName = models.ForeignKey(SecGroup, on_delete=models.CASCADE)

from django.contrib import admin
from .models import AwsKey, SecGroup, SecGroupPermission

# Register your models here.

admin.site.register(AwsKey)
admin.site.register(SecGroup)
admin.site.register(SecGroupPermission)

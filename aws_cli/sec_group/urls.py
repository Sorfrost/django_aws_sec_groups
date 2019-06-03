from django.urls import path

from . import views

urlpatterns = [
    path('', views.mainpage_sec, name='index'),
    path('authorize_ingress_sec', views.authorize_ingress_sec, name='authorize_ingress'),
    path('revoke_ingress_sec', views.revoke_ingress_sec, name='authorize_ingress')
]
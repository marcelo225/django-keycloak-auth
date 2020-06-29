from rest_framework.routers import DefaultRouter
from django.urls import path
from . import views


router = DefaultRouter(trailing_slash=False)
router.register('banks', views.BankViewSet)
router.register('cars', views.CarViewSet, basename="car")
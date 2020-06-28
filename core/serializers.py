from rest_framework import serializers
from . import models


class BankSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.Bank
        fields = '__all__'
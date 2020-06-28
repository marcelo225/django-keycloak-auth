from rest_framework import viewsets
from . import models, serializers
from rest_framework import status
from django.http.response import JsonResponse
from rest_framework.exceptions import PermissionDenied, AuthenticationFailed, NotAuthenticated


class BankViewSet(viewsets.ModelViewSet):
    """
    Bank endpoint    
    This endpoint has all configured keycloak roles    
    """
    serializer_class = serializers.BankSerializer
    queryset = models.Bank.objects.all()    
    keycloak_roles = {
        'GET': ['director', 'judge', 'employee'],
        'POST': ['director', 'judge', ],
        'UPDATE': ['director', 'judge', ],
        'DELETE': ['director', 'judge', ],
        'PATCH': ['director', 'judge', 'employee'],
    }

    def list(self, request):
        """
        Overwrite method
        You can especify your rules inside each method 
        using the variable 'request.roles' that means a
        list of roles that came from authenticated token.
        See the following example bellow:
        """
        if request.roles == 'director':
            return JsonResponse({"detail": PermissionDenied.default_detail}, status=PermissionDenied.status_code)    
        return super().list(self, request)


class CarViewSet(viewsets.ViewSet):
    """
    Car endpoint
    This endpoint has not configured keycloak roles
    """
    
    def list(self, request):
        return JsonResponse({"detail": "success"}, status=status.HTTP_200_OK)


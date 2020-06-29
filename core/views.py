from rest_framework import viewsets, views
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
        # list of token roles
        print(request.roles)        
        return super().list(self, request)


class CarViewSet(viewsets.ViewSet):
    """
    Car endpoint
    This endpoint has not configured keycloak roles. 
    That means all methods will be allowed to access.
    """    
    def list(self, request):
        return JsonResponse({"detail": "success"}, status=status.HTTP_200_OK)


class JudgementView(views.APIView):
    """
    Judgement endpoint
    This endpoint has configured keycloak roles only GET method.
    Other HTTP methods will be allowed.
    """
    keycloak_roles = {
        'GET': ['judge'],
    }
    
    def get(self, request, format=None):
        """
        Overwrite method
        You can especify your rules inside each method 
        using the variable 'request.roles' that means a
        list of roles that came from authenticated token.
        See the following example bellow:
        """
        # list of token roles
        print(request.roles)
        return super().get(self, request) 


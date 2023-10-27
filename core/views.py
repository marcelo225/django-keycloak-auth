from rest_framework import viewsets, views
from . import models, serializers
from rest_framework import status
from rest_framework.decorators import api_view
from django.http.response import JsonResponse
from django_keycloak_auth.decorators import keycloak_roles

class BankViewSet(viewsets.ModelViewSet):
    """
    Bank endpoint    
    This endpoint has all configured keycloak roles    
    """
    serializer_class = serializers.BankSerializer
    queryset = models.Bank.objects.all()    
    keycloak_roles = {
        'GET': ['director', 'judge', 'employee'],
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
        
        # Optional: get userinfo (SUB attribute from JWT)
        print(request.userinfo)
        
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
        return JsonResponse({"message": request.roles})


@keycloak_roles(['director', 'judge', 'employee'])
@api_view(['GET'])
def loans(request):
    """
    List loan endpoint
    This endpoint has configured keycloak roles only GET method 
    and only GET methods will be accepted in api_view.
    """
    return JsonResponse({"message": request.roles})
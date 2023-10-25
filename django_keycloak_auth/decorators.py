from django.utils.decorators import decorator_from_middleware_with_args
from .middleware import KeycloakMiddleware
from django.http.response import JsonResponse
from rest_framework.exceptions import PermissionDenied
from functools import wraps


def keycloak_roles(access_roles: list):
    """Decorator for keycloak_roles apply for api functions based views.

    Args:
        access_roles (list): List of keycloak roles to apply authorization
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapped_func(request, *args, **kwargs):
            if len(set(request.roles) & set(access_roles)) == 0:
                return JsonResponse({'detail': PermissionDenied.default_detail}, status=PermissionDenied.status_code)
            return view_func(request, *args, **kwargs)
        return wrapped_func
    return decorator
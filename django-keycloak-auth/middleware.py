# ========================================================================
# KeycloakMiddleware
# Middleware responsible for intercepting authentication tokens.
#
# Copyright (C) 2020 Marcelo Vinicius de Sousa Campos <mr.225@hotmail.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import re
import requests
from .keycloak import KeycloakConnect
from django.conf import settings
from django.http.response import JsonResponse
from rest_framework.exceptions import PermissionDenied, AuthenticationFailed, NotAuthenticated


class KeycloakMiddleware:

    def __init__(self, get_response):
        
        # Set configurations from the settings file
        self.config = settings.KEYCLOAK_CONFIG
        
        # Django response
        self.get_response = get_response

        # Read keycloak configurations and set each attribute
        try:
            self.server_url = self.config['KEYCLOAK_SERVER_URL']
            self.realm = self.config['KEYCLOAK_REALM']
            self.client_id = self.config['KEYCLOAK_CLIENT_ID']
            self.client_secret_key = self.config['KEYCLOAK_CLIENT_SECRET_KEY']            
        except KeyError as e:
            raise Exception("The mandatory KEYCLOAK configuration variables has not defined.")

        if self.config['KEYCLOAK_SERVER_URL'] is None:
            raise Exception("The mandatory KEYCLOAK_SERVER_URL configuration variables has not defined.")
            
        if self.config['KEYCLOAK_REALM'] is None:
            raise Exception("The mandatory KEYCLOAK_REALM configuration variables has not defined.")
            
        if self.config['KEYCLOAK_CLIENT_ID'] is None:
            raise Exception("The mandatory KEYCLOAK_CLIENT_ID configuration variables has not defined.")
            
        if self.config['KEYCLOAK_CLIENT_SECRET_KEY'] is None:
            raise Exception("The mandatory KEYCLOAK_CLIENT_SECRET_KEY configuration variables has not defined.")

        # Create Keycloak instance
        self.keycloak = KeycloakConnect(server_url=self.server_url,
                                        realm_name=self.realm,
                                        client_id=self.client_id,
                                        client_secret_key=self.client_secret_key)

    def __call__(self, request):
        return self.get_response(request)

    def process_view(self, request, view_func, view_args, view_kwargs):

        # for now there is no role assigned yet
        request.roles = []

        # Checks the URIs (paths) that doesn't needs authentication        
        if hasattr(settings, 'KEYCLOAK_EXEMPT_URIS'):
            path = request.path_info.lstrip('/')
            if any(re.match(m, path) for m in settings.KEYCLOAK_EXEMPT_URIS):
                return None
        
        # Read if View has attribute 'keycloak_roles'
        # Whether View hasn't this attribute, it means all request method routes will be permitted.        
        try:
            view_roles = view_func.cls.keycloak_roles
        except AttributeError as e:
            return None
        
        # Select actual role from 'keycloak_roles' according http request method (GET, POST, PUT or DELETE)
        require_view_role = view_roles.get(request.method, [None])        

        # Checks if exists an authentication in the http request header        
        if 'HTTP_AUTHORIZATION' not in request.META:
            return JsonResponse({"detail": NotAuthenticated.default_detail}, status=NotAuthenticated.status_code)
        
        # Get access token in the http request header
        auth_header = request.META.get('HTTP_AUTHORIZATION').split()
        token = auth_header[1] if len(auth_header) == 2 else auth_header[0]
        
        # Checks token is active
        if not self.keycloak.is_token_active(token):
            return JsonResponse(
                {"detail": "Invalid or expired token. Verify your Keycloak configuration."}, 
                status=AuthenticationFailed.status_code
            )        
        
        # Get roles from access token
        token_roles = self.keycloak.roles_from_token(token)
        if token_roles is None:
            return JsonResponse(
                {'detail': 'This token has no client_id roles and no realm roles or client_id is not configured '
                           'correctly.'},
                status=AuthenticationFailed.status_code
            )
        
        # Check exists any Token Role contains in View Role
        if len(set(token_roles) & set(require_view_role)) == 0:
            return JsonResponse({'detail': PermissionDenied.default_detail}, status=PermissionDenied.status_code)
        
        # Add to View request param list of roles from authenticated token
        request.roles = token_roles

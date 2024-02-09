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

import logging
import re
from .keycloak import KeycloakConnect
from django.conf import settings
from django.http.response import JsonResponse
from rest_framework.exceptions import PermissionDenied, AuthenticationFailed, NotAuthenticated

LOGGER = logging.getLogger(__name__)

class KeycloakConfig:

    def __init__(self):

        # Set configurations from the settings file
        config = settings.KEYCLOAK_CONFIG

        # Read keycloak configurations and set each attribute
        try:
            self.server_url = config['KEYCLOAK_SERVER_URL']
            self.realm = config['KEYCLOAK_REALM']
            self.client_id = config['KEYCLOAK_CLIENT_ID']
            self.client_secret_key = config['KEYCLOAK_CLIENT_SECRET_KEY']
        except KeyError:
            raise ValueError("The mandatory KEYCLOAK configuration variables has not defined.")

        if config['KEYCLOAK_SERVER_URL'] is None:
            raise ValueError("The mandatory KEYCLOAK_SERVER_URL configuration variables has not defined.")

        if config['KEYCLOAK_REALM'] is None:
            raise ValueError("The mandatory KEYCLOAK_REALM configuration variables has not defined.")

        if config['KEYCLOAK_CLIENT_ID'] is None:
            raise ValueError("The mandatory KEYCLOAK_CLIENT_ID configuration variables has not defined.")

        if config['KEYCLOAK_CLIENT_SECRET_KEY'] is None:
            raise ValueError("The mandatory KEYCLOAK_CLIENT_SECRET_KEY configuration variables has not defined.")  
        
        if config.get('LOCAL_DECODE') is None:
            self.local_decode = False
        elif not isinstance(config.get('LOCAL_DECODE'), bool):
            raise ValueError("The LOCAL_DECODE configuration variable must be True or False.")
        else:
            self.local_decode = config.get('LOCAL_DECODE')
        
        self.audience = config.get('KEYCLOAK_AUDIENCE')


class KeycloakMiddleware:

    def __init__(self, get_response):
        
        # Read Keycloak configurations
        self.keycloak_config = KeycloakConfig()

        # Django response
        self.get_response = get_response

        # Create Keycloak instance
        self.keycloak = KeycloakConnect(server_url=self.keycloak_config.server_url,
                                        realm_name=self.keycloak_config.realm,
                                        client_id=self.keycloak_config.client_id,
                                        local_decode=self.keycloak_config.local_decode,
                                        client_secret_key=self.keycloak_config.client_secret_key,
                                        audience=self.keycloak_config.audience)

    def __call__(self, request):
        return self.get_response(request)      

    def process_view(self, request, view_func, view_args, view_kwargs):

        # for now there is no role assigned yet and no userinfo defined
        request.roles = []
        request.userinfo = []
        if not self.check_uris_path(request, view_func):
            return None
        # There's condictions for these view_func.cls:
        # 1) @api_view -> view_func.cls is WrappedAPIView (validates in 'keycloak_roles' in decorators.py) -> True
        # 2) When it is a APIView, ViewSet or ModelViewSet with 'keycloak_roles' attribute -> False
        try:
            is_api_view = True if str(view_func.cls.__qualname__) == "WrappedAPIView" else False
        except AttributeError:
            is_api_view = False

        # Read if View has attribute 'keycloak_roles' (for APIView, ViewSet or ModelViewSet)
        # Whether View hasn't this attribute, it means all request method routes will be permitted.        
        try:
            view_roles = view_func.cls.keycloak_roles if not is_api_view else None
        except AttributeError:
            return None

        # Checks if exists an authentication in the http request header
        if 'HTTP_AUTHORIZATION' not in request.META:
            return JsonResponse(
                {"detail": NotAuthenticated.default_detail},
                status=NotAuthenticated.status_code
            )

        # Select actual role from 'keycloak_roles' according http request method
        require_role = view_roles.get(request.method, [None]) if not is_api_view else [None]

        # Get access token from the http request header
        auth_header = request.META.get('HTTP_AUTHORIZATION').split()
        token = auth_header[1] if len(auth_header) == 2 else auth_header[0]

        try:
            token_payload = self.get_payload(token, self.keycloak_config.local_decode)
        except Exception:
            return JsonResponse(
                {"detail": "Invalid or expired token. Verify your Keycloak configuration."}, 
                status=AuthenticationFailed.status_code
            )

        token_roles = self.keycloak.roles_from_token(token_payload)
        if token_roles is None:
            return JsonResponse(
                {'detail': 'This token has no client_id roles and no realm roles or client_id is not configured correctly.'},
                status=AuthenticationFailed.status_code
            )

        if not is_api_view and (len(set(token_roles) & set(require_role)) == 0):
            return JsonResponse(
                {'detail': PermissionDenied.default_detail},
                status=PermissionDenied.status_code
            )

        request.roles = token_roles
        request.userinfo = token_payload

    def check_uris_path(self, request, view_func):
        """Checks the URIs (paths) that doesn't needs authentication"""
        if hasattr(settings, 'KEYCLOAK_EXEMPT_URIS'):
            path = request.path_info.lstrip('/')
            if any(re.match(m, path) for m in settings.KEYCLOAK_EXEMPT_URIS):
                request_method = request.method not in view_func.cls.keycloak_roles
                if hasattr(view_func.cls, "keycloak_roles") and request_method:
                    return False
        return True

    def get_payload(self, token, local_decode):
        '''Получение payload из токена'''
        if local_decode:
            payload_token = self.keycloak.decode(
                token,
                options={'verify_signature': True,"verify_exp": True}
            )
        else:
            payload_token = self.keycloak.introspect(token)
        return payload_token

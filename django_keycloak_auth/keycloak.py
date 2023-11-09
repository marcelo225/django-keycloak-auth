# ========================================================================
# KeycloakConnect
# Utility class that will perform communications with the Keycloak.
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

import json
import jwt
import requests
import logging

from base64 import b64decode
from cryptography.hazmat.primitives import serialization
from django.core.cache import cache
from jwt.exceptions import DecodeError, ExpiredSignatureError
from requests import HTTPError

LOGGER = logging.getLogger(__name__)


class KeycloakConnect:
    def __init__(self, server_url, realm_name, client_id, local_decode=False, client_secret_key=None, ):
        """Create Keycloak Instance.

        Args:
            server_url (str): 
                URI auth server
            realm_name (str): 
                Realm name
            client_id (str): 
                Client ID
            client_secret_key (str, optional): 
                Client secret credentials.
                For each 'access type':
                    - bearer-only -> Optional
                    - public -> Mandatory
                    - confidential -> Mandatory
        
        Returns:
            object: Keycloak object
        """

        self.server_url = server_url
        self.realm_name = realm_name
        self.client_id = client_id
        self.client_secret_key = client_secret_key
        self.local_decode = local_decode

        # Keycloak useful Urls
        self.well_known_endpoint = (
            self.server_url
            + "/realms/"
            + self.realm_name
            + "/.well-known/openid-configuration"
        )
        self.token_introspection_endpoint = (
            self.server_url
            + "/realms/"
            + self.realm_name
            + "/protocol/openid-connect/token/introspect"
        )
        self.userinfo_endpoint = (
            self.server_url
            + "/realms/"
            + self.realm_name
            + "/protocol/openid-connect/userinfo"
        )
        self.jwks_endpoint = (
            self.server_url
            + "/realms/"
            + self.realm_name
            + "/protocol/openid-connect/certs"
        )

    @staticmethod
    def _send_request(method, url, **kwargs):
        """Send request by method and url.
         Raises HTTPError exceptions if status >= 400

         Returns:
             json: Response body
         """
        response = requests.request(method, url, **kwargs)
        response.raise_for_status()
        return response.json()

    def well_known(self, raise_exception=True):
        """Lists endpoints and other configuration options 
        relevant to the OpenID Connect implementation in Keycloak.

        Args:
            raise_exception: Raise exception if the request ended with a status >= 400.

        Returns:
            [type]: [list of keycloak endpoints]
        """
        try:
            response = self._send_request("GET", self.well_known_endpoint)
        except HTTPError as ex:
            LOGGER.error(
                "Error obtaining list of endpoints from endpoint: "
                f"{self.well_known_endpoint}, response error {ex}"
            )
            if raise_exception:
                raise
            return {}
        return response
    
    def jwks(self, raise_exception=True):
        """Dictionary of the OpenID Connect keys in Keycloak.

        Args:
            raise_exception: Raise exception if the request ended with a status >= 400.

        Returns:
            [type]: [Dictionary of keycloak keys]
        """
        response = cache.get('jwks')

        try:
            if response is None:
                response = self._send_request("GET", self.jwks_endpoint)
                cache.set('jwks', response)
        except HTTPError as ex:
            LOGGER.error(
                "Error obtaining dictionary of keys from endpoint: "
                f"{self.jwks_endpoint}, response error {ex}"
            )
            if raise_exception:
                raise
            return {}

        return response

    def introspect(self, token, token_type_hint=None, raise_exception=True):
        """
        Introspection Request token
        Implementation: https://tools.ietf.org/html/rfc7662#section-2.1

        Args:
            token (string): 
                REQUIRED. The string value of the token.  For access tokens, this
                is the "access_token" value returned from the token endpoint
                defined in OAuth 2.0 [RFC6749], Section 5.1.  For refresh tokens,
                this is the "refresh_token" value returned from the token endpoint
                as defined in OAuth 2.0 [RFC6749], Section 5.1.  Other token types
                are outside the scope of this specification.
            token_type_hint ([string], optional): 
                OPTIONAL.  A hint about the type of the token submitted for
                introspection.  The protected resource MAY pass this parameter to
                help the authorization server optimize the token lookup.  If the
                server is unable to locate the token using the given hint, it MUST
                extend its search across all of its supported token types.  An
                authorization server MAY ignore this parameter, particularly if it
                is able to detect the token type automatically.  Values for this
                field are defined in the "OAuth Token Type Hints" registry defined
                in OAuth Token Revocation [RFC7009].
            raise_exception: Raise exception if the request ended with a status >= 400.

        Returns:
            json: The introspect token
        """
        payload = {
            "token": token,
            "client_id": self.client_id,
            "client_secret": self.client_secret_key,
        }
        headers = {
            "content-type": "application/x-www-form-urlencoded",
            "authorization": "Bearer " + token,
        }
        try:
            response = self._send_request(
                "POST", self.token_introspection_endpoint, data=payload, headers=headers)
        except HTTPError as ex:
            LOGGER.error(
                "Error obtaining introspect token from endpoint: "
                f"{self.token_introspection_endpoint}, data {payload}, "
                f" headers {headers}, response error {ex}"
            )
            if raise_exception:
                raise
            return {}
        return response

    def is_token_active(self, token, raise_exception=True):
        """Verify if introspect token is active.

        Args:
            token (str): The string value of the token.
            raise_exception: Raise exception if the request ended with a status >= 400.

        Returns:
            boolean: Token valid (True) or invalid (False)
        """

        if self.local_decode:
            try:
                self.decode(token, options={"verify_exp": True}, raise_exception=raise_exception)
                is_active = True
            except ExpiredSignatureError as e:
                is_active = False
        else:
            introspect_token = self.introspect(token, raise_exception)
            is_active = introspect_token.get("active", None)

        return True if is_active else False

    def roles_from_token(self, token, raise_exception=True):
        """
        Get roles from token

        Args:
            token (string): The string value of the token.
            raise_exception: Raise exception if the request ended with a status >= 400.

        Returns:
            list: List of roles.
        """
        if self.local_decode:
            token_decoded = self.decode(token, raise_exception=raise_exception)
        else:
            token_decoded = self.introspect(token, raise_exception)

        realm_access = token_decoded.get("realm_access", None)
        resource_access = token_decoded.get("resource_access", None)
        client_access = (
            resource_access.get(self.client_id, None)
            if resource_access is not None
            else None
        )

        client_roles = (
            client_access.get("roles", None) if client_access is not None else None
        )
        realm_roles = (
            realm_access.get("roles", None) if realm_access is not None else None
        )

        if client_roles is None:
            return realm_roles
        if realm_roles is None:
            return client_roles
        return client_roles + realm_roles

    def userinfo(self, token, raise_exception=True):
        """Get userinfo (sub attribute from JWT) from authenticated token

        Args:
            token (str): The string value of the token.
            raise_exception: Raise exception if the request ended with a status >= 400.

        Returns:
            json: user info data
        """
        headers = {"authorization": "Bearer " + token}
        try:
            if self.local_decode:
                response = self.decode(token, raise_exception=raise_exception)
            else:
                response = self._send_request(
                    "GET", self.userinfo_endpoint, headers=headers)
        except HTTPError as ex:
            LOGGER.error(
                "Error obtaining userinfo token from endpoint: "
                f"{self.userinfo_endpoint}, headers {headers}, "
                f"response error {ex}"
            )
            if raise_exception:
                raise
            return {}
        
        return response

    def decode(self, token, audience=None, options=None, raise_exception=True):
        """Decodes token.

        Args:
            token (str): The string value of the token
            audience (str | List[str] | None): The audience to validate
            options (dict): The options for jwt.decode https://pyjwt.readthedocs.io/en/stable/api.html?highlight=options
            raise_exception: Raise exception the token cannot be decoded or validated

        Returns:
            json: decoded token
        """

        if audience is None:
            audience = self.client_id

        jwks = self.jwks()
        keys = jwks.get('keys', [])
        
        public_keys = {}
        for jwk in keys:
            kid = jwk.get('kid')
            if kid:
                public_keys[kid] = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwk))

        kid = jwt.get_unverified_header(token).get('kid', '')
        key = public_keys.get(kid, '')

        try:
            payload = jwt.decode(token, key=key, algorithms=['RS256'], audience=audience, options=options)
        except Exception as ex:
            LOGGER.error(
                f"Error decoding token {ex}"
            )
            if raise_exception:
                raise
            return {}

        return payload


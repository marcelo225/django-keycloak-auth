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

import requests
from jose import jwt
from django.http.response import JsonResponse


class KeycloakConnect:
    
    def __init__(self, server_url, realm_name, client_id, realm_public_key=None, client_secret_key=None, realm_algorithm='RS256'):
        """Create Keycloak Instance.

        Args:
            server_url (str): 
                URI auth server
            realm_name (str): 
                Realm name
            client_id (str): 
                Client ID
            realm_public_key (str, optional): 
                Realm public key. 
                You can get it in in menu: REALMS > 'Key' tab. 
                - encode/decode token -> Mandatory
                - introspect token -> Not use
                
            client_secret_key (str, optional): 
                Client secret credencials.
                For each 'access type':
                    - bearer-only -> Optional
                    - public -> Mandatory
                    - confidencial -> Mandatory

            realm_algorithm (str, optional): 
                Algorithm used to encript/deecript token. 
                - encode/decode token -> Mandatory
                - introspect token -> Not use
                Defaults to 'RS256'.
        
        Returns:
            object: Keycloak object
        """

        self.server_url = server_url
        self.realm_name = realm_name
        self.client_id = client_id
        self.client_secret_key = client_secret_key
        self.realm_public_key = realm_public_key
        self.realm_algorithm = realm_algorithm

        # Keycloak useful Urls
        self.well_known_endpoint = self.server_url + "realms/" + self.realm_name + "/.well-known/openid-configuration"
        self.authorization_endpoint = self.server_url + "realms/" + self.realm_name + "/protocol/openid-connect/auth"
        self.token_endpoint = self.server_url + "realms/" + self.realm_name + "/protocol/openid-connect/token"
        self.token_introspection_endpoint = self.server_url + "realms/" + self.realm_name + "/protocol/openid-connect/token/introspect"
        self.userinfo_endpoint = self.server_url + "realms/" + self.realm_name + "/protocol/openid-connect/userinfo"
        self.end_session_endpoint = self.server_url + "realms/" + self.realm_name + "/protocol/openid-connect/logout"

    def well_known(self):
        """Lists endpoints and other configuration options 
        relevant to the OpenID Connect implementation in Keycloak.

        Returns:
            [type]: [list of keycloak endpoints]
        """
        response = requests.request("GET", self.well_known_endpoint)
        return response.json()
    
    def introspect(self, token, token_type_hint=None):
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

        Returns:
            json: The introspect token
        """        
        payload = {
            "token": token,
            "client_id": self.client_id,
            "client_secret": self.client_secret_key
        }
        headers = {
            'content-type': "application/x-www-form-urlencoded",
            'authorization': "Bearer " + token
        }
        
        response = requests.request("POST", self.token_introspection_endpoint, data=payload, headers=headers)
        return response.json()
    
    def is_token_active(self, token):
        """Verify if introspect token is active.

        Args:
            token (str): The string value of the token. 

        Returns:
            bollean: Token valid (True) or invalid (False)
        """
        introspect_token = self.introspect(token)
        is_active = introspect_token.get('active', None)       
        return True if is_active else False

    def roles_from_token(self, token):
        """
        Get roles from token

        Args:
            token (string): The string value of the token.

        Returns:
            list: List of roles.
        """
        token_decoded = self.introspect(token)
        resource_access = token_decoded['resource_access'].get(self.client_id, None)
        return resource_access.get('roles', None)

    def encode_token(self, string):
        return jwt.encode(string, self.realm_public_key, algorithm=self.realm_algorithm)

    def decode_token(self, token):
        return jwt.decode(token, self.realm_public_key, algorithms=[self.realm_algorithm])

    def userinfo(self, token):
        """Get user info from authenticated token

        Args:
            token (str): The string value of the token. 

        Returns:
            json: user info data            
        """
        headers = {
            'authorization': "Bearer " + token
        }
        response = requests.request("GET", self.userinfo_endpoint, headers=headers)
        return response.json()

    def authorization(self):
        """
        Not implementated
        """
        pass
    
    def login(self):
        """
        Not implementated
        """
        pass

    def logout(self):
        """
        Not implementated
        """
        pass    
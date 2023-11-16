from django.test import TestCase, Client, RequestFactory
from requests import HTTPError
from rest_framework import status
from django.conf import settings
from .middleware import KeycloakMiddleware, KeycloakConnect
from core import views
from unittest.mock import Mock


class KeycloakConfigTestCase(TestCase):

    def setUp(self):
        self.uri = '/core/banks'
        self.client = Client()
        self.factory = RequestFactory()        
        KeycloakConnect.userinfo = Mock(return_value={})

    def tearDown(self):
        settings.KEYCLOAK_EXEMPT_URIS = []
        settings.KEYCLOAK_CONFIG['KEYCLOAK_SERVER_URL'] = 'http://localhost:8080/auth'
        settings.KEYCLOAK_CONFIG['KEYCLOAK_REALM'] = 'TEST'
        settings.KEYCLOAK_CONFIG['KEYCLOAK_CLIENT_ID'] = 'client-backend'
        settings.KEYCLOAK_CONFIG['KEYCLOAK_CLIENT_SECRET_KEY'] = '41ab4e22-a6f3-4bef-86e3-f2a1c97d6387'

    def test_when_has_not_some_keycloak_configuration_settings(self):
        # GIVEN doesn't configurated keycloak django settings
        del settings.KEYCLOAK_CONFIG['KEYCLOAK_SERVER_URL']        

        # WHEN makes a request
        # THEN throws configuration exception
        with self.assertRaises(Exception):
            self.client.get(self.uri)
            KeycloakMiddleware(Mock)(self.request)

    def test_when_has_not_keycloak_server_url_configuration_settings(self):
        # GIVEN None value KEYCLOAK_SERVER_URL django settings
        settings.KEYCLOAK_CONFIG['KEYCLOAK_SERVER_URL'] = None

        # WHEN makes a request
        # THEN throws configuration exception
        with self.assertRaises(Exception):
            self.client.get(self.uri)
            KeycloakMiddleware(Mock)(self.request)

    def test_when_has_not_keycloak_realm_configuration_settings(self):
        # GIVEN None value KEYCLOAK_REALM django settings
        settings.KEYCLOAK_CONFIG['KEYCLOAK_REALM'] = None

        # WHEN makes a request
        # THEN throws configuration exception
        with self.assertRaises(Exception):
            self.client.get(self.uri)
            KeycloakMiddleware(Mock)(self.request)

    def test_when_has_not_keycloak_client_secret_key_configuration_settings(self):
        # GIVEN None value KEYCLOAK_CLIENT_SECRET_KEY django settings
        settings.KEYCLOAK_CONFIG['KEYCLOAK_CLIENT_SECRET_KEY'] = None

        # WHEN makes a request
        # THEN throws configuration exception
        with self.assertRaises(Exception):
            self.client.get(self.uri)
            KeycloakMiddleware(Mock)(self.request)

    def test_when_has_not_keycloak_client_id_configuration_settings(self):
        # GIVEN None value KEYCLOAK_CLIENT_ID django settings
        settings.KEYCLOAK_CONFIG['KEYCLOAK_CLIENT_ID'] = None

        # WHEN makes a request
        # THEN throws configuration exception
        with self.assertRaises(Exception):
            self.client.get(self.uri)
            KeycloakMiddleware(Mock)(self.request)


class KeycloakMiddlewareTestCase(TestCase):

    def setUp(self):
        self.uri = '/core/banks'
        self.client = Client()
        self.factory = RequestFactory()        
        KeycloakConnect.userinfo = Mock(return_value={})
        self.keycloak = KeycloakConnect(
            settings.KEYCLOAK_CONFIG['KEYCLOAK_REALM'],
            settings.KEYCLOAK_CONFIG['KEYCLOAK_REALM'],
            settings.KEYCLOAK_CONFIG['KEYCLOAK_CLIENT_ID'],
        )

    def tearDown(self):
        settings.KEYCLOAK_EXEMPT_URIS = []
        settings.KEYCLOAK_CONFIG['KEYCLOAK_SERVER_URL'] = 'http://localhost:8080/auth'
        settings.KEYCLOAK_CONFIG['KEYCLOAK_REALM'] = 'TEST'
        settings.KEYCLOAK_CONFIG['KEYCLOAK_CLIENT_ID'] = 'client-backend'
        settings.KEYCLOAK_CONFIG['KEYCLOAK_CLIENT_SECRET_KEY'] = '41ab4e22-a6f3-4bef-86e3-f2a1c97d6387'

    def test_when_some_EXEMPT_URI_is_permitted_on_authentication_with_keycloak_roles_on_view(self):
        # GIVEN that a URL has been given that it will fire without authorization
        settings.KEYCLOAK_EXEMPT_URIS = ['core/banks']

        # WHEN makes a request that has 'keycloak_roles' attribute on View
        get_response = self.client.get(self.uri)
        post_response = self.client.post(self.uri, {"name": "fake", "code": "test"})

        # THEN allows endpoint to be accessed
        self.assertEqual(get_response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(post_response.status_code, status.HTTP_201_CREATED)

    def test_when_some_URI_is_permitted_on_authentication_without_keycloak_roles_attribute_on_view(self):
        # GIVEN i've got a URI without 'keycloak_roles' on the View
        uri_no_roles = '/core/cars'

        # WHEN makes a request
        response = self.client.get(uri_no_roles)

        # THEN allows endpoint to be accessed
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_when_some_URI_without_authorization_on_http_header(self):
        # GIVEN a View endpoint
        view = views.BankViewSet.as_view({'get': 'list'})

        # WHEN makes GET request without HTTP_AUTHORIZATIOND
        request = self.factory.get(self.uri)
        response = KeycloakMiddleware(Mock()).process_view(request, view, [], {})        

        # THEN not allows endpoint to be accessed (401)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_when_token_not_active(self):
        # GIVEN token as not valid
        KeycloakConnect.is_token_active = Mock(return_value=False)        

        # GIVEN a View endpoint
        view = views.BankViewSet.as_view({'get': 'list'})

        # GIVEN a fake request
        request = self.factory.get(self.uri)
        request.META['HTTP_AUTHORIZATION'] = 'Bearer token'

        # WHEN middleware is processed
        response = KeycloakMiddleware(Mock()).process_view(request, view, [], {})

        # THEN not allows endpoint to be accessed (401)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_when_token_as_active_and_no_roles_request_not_authorizated(self):
        # GIVEN token as valid
        KeycloakConnect.is_token_active = Mock(return_value=True)

        # GIVEN token has no roles
        KeycloakConnect.roles_from_token = Mock(return_value=None)

        # GIVEN a View endpoint
        view = views.BankViewSet.as_view({'get': 'list'})

        # GIVEN a fake request
        request = self.factory.get(self.uri)
        request.META['HTTP_AUTHORIZATION'] = 'Bearer token_fake'

        # WHEN middleware is processed
        response = KeycloakMiddleware(Mock()).process_view(request, view, [], {})

        # THEN not allows endpoint to be accessed (401)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_when_token_as_active_and_has_roles_request_not_authorizated(self):
        # GIVEN token as valid
        KeycloakConnect.is_token_active = Mock(return_value=True)

        # GIVEN token has different role
        KeycloakConnect.roles_from_token = Mock(return_value=['xxxxxx'])

        # GIVEN a View endpoint has a 'diretor' role on GET method
        view = views.BankViewSet.as_view({'get': 'list'})
        view.keycloak_roles = {'GET': ['director']}

        # GIVEN a fake request
        request = self.factory.get(self.uri)
        request.META['HTTP_AUTHORIZATION'] = 'Bearer token_fake'

        # WHEN middleware is processed
        response = KeycloakMiddleware(Mock()).process_view(request, view, [], {})

        # THEN does't allow endpoint authorization
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_when_token_as_active_and_has_roles_request_authorizated(self):
        # GIVEN token as valid
        KeycloakConnect.is_token_active = Mock(return_value=True)

        # GIVEN token has roles
        KeycloakConnect.roles_from_token = Mock(return_value=['director'])

        # GIVEN a View endpoint has a 'diretor' role on GET method
        view = views.BankViewSet.as_view({'get': 'list'})
        view.keycloak_roles = {'GET': ['director']}

        # GIVEN a fake request
        request = self.factory.get(self.uri)
        request.META['HTTP_AUTHORIZATION'] = 'Bearer token_fake'

        # WHEN middleware is processed
        response = KeycloakMiddleware(Mock()).process_view(request, view, [], {})

        # THEN allows endpoint and pass token roles to request View
        self.assertEqual(['director'], request.roles)

    def test_when_realm_roles_and_client_roles_are_present_both_are_returned(self):
        fake_token = {
            "realm_access": {
                "roles": [
                    "director",
                ]
            },
            "resource_access": {
                settings.KEYCLOAK_CONFIG['KEYCLOAK_CLIENT_ID']: {
                    "roles": [
                        "judge"
                    ]
                }
            }}
        self.keycloak.introspect = Mock(return_value=fake_token)
        self.keycloak.userinfo = Mock(return_value=fake_token)
        roles = self.keycloak.roles_from_token(Mock())

        self.assertEqual(['judge', 'director'], roles)

    def test_when_only_realm_roles_are_present_realm_roles_are_returned(self):
        fake_token = {
            "realm_access": {
                "roles": [
                    "director",
                ]
            },
        }
        self.keycloak.introspect = Mock(return_value=fake_token)
        self.keycloak.userinfo = Mock(return_value=fake_token)
        roles = self.keycloak.roles_from_token(Mock())

        self.assertEqual(['director'], roles)

    def test_when_only_client_roles_are_present_client_roles_are_returned(self):
        fake_token = {
            "resource_access": {
                settings.KEYCLOAK_CONFIG['KEYCLOAK_CLIENT_ID']: {
                    "roles": [
                        "judge"
                    ]
                }
            }
        }
        self.keycloak.introspect = Mock(return_value=fake_token)
        self.keycloak.userinfo = Mock(return_value=fake_token)
        roles = self.keycloak.roles_from_token(Mock())

        self.assertEqual(['judge'], roles)

    def test_when_no_role_is_present_none_is_returned(self):
        fake_token = {}
        self.keycloak.introspect = Mock(return_value=fake_token)
        self.keycloak.userinfo = Mock(return_value=fake_token)
        roles = self.keycloak.roles_from_token(Mock())

        self.assertEqual(None, roles)
    
    def test_when_only_user_info_is_present_user_info_are_returned(self):
        fake_token = {
            "sub": "d0a45bca-edf3-4334-a195-db827349a52d",
            "email_verified": False,
            "preferred_username": "test-api"
        }
        self.keycloak.introspect = Mock(return_value=fake_token)
        self.keycloak.userinfo = Mock(return_value=fake_token)
        
        userinfo = self.keycloak.userinfo(Mock())
        
        self.assertEqual(fake_token['sub'], userinfo['sub'])

    def test_keycloak_connect_well_known(self):
        """Test keycloak endpoint well_known when status >= 400"""        
        self.keycloak._send_request = Mock(side_effect=HTTPError)
        result = self.keycloak.well_known(raise_exception=False)
        self.assertDictEqual({}, result)

        with self.assertRaises(HTTPError):
            self.keycloak.well_known()

    def test_keycloak_connect_introspect(self):
        """Test keycloak endpoint introspect when status >= 400"""
        self.keycloak._send_request = Mock(side_effect=HTTPError)
        result = self.keycloak.introspect('', raise_exception=False)
        self.assertDictEqual({}, result)

        with self.assertRaises(HTTPError):
            self.keycloak.introspect('')

    def test_keycloak_connect_introspect(self):
        """Test keycloak endpoint introspect when status >= 400"""
        self.keycloak._send_request = Mock(side_effect=HTTPError)
        result = self.keycloak.jwks(raise_exception=False)
        self.assertDictEqual({}, result)

        with self.assertRaises(HTTPError):
            self.keycloak.introspect('')


class KeycloakRolesDecoratorTestCase(TestCase):

    def setUp(self):
        self.uri = '/loans'
        self.client = Client()
        self.factory = RequestFactory()
        self.fake_userinfo = {
            'sub': 'sid-test', 
            'email_verified': False, 
            'preferred_username': 'test'
        }

    def tearDown(self):
        settings.KEYCLOAK_EXEMPT_URIS = []
        settings.KEYCLOAK_CONFIG['KEYCLOAK_SERVER_URL'] = 'http://localhost:8080/auth'
        settings.KEYCLOAK_CONFIG['KEYCLOAK_REALM'] = 'TEST'
        settings.KEYCLOAK_CONFIG['KEYCLOAK_CLIENT_ID'] = 'client-backend'
        settings.KEYCLOAK_CONFIG['KEYCLOAK_CLIENT_SECRET_KEY'] = '41ab4e22-a6f3-4bef-86e3-f2a1c97d6387'

    def test_when_token_is_active_and_has_roles_request_not_authorizated(self):
        
        # GIVEN token as valid
        KeycloakConnect.is_token_active = Mock(return_value=True)

        # GIVEN token has no roles
        KeycloakConnect.roles_from_token = Mock(return_value=None)

        # GIVEN userinfo from fake token
        KeycloakConnect.userinfo = Mock(return_value=self.fake_userinfo)

        # GIVEN a View endpoint
        view = views.loans

        # GIVEN a fake request
        request = self.factory.get(self.uri)
        request.META['HTTP_AUTHORIZATION'] = 'Bearer token_fake'

        # WHEN middleware is processed
        response = KeycloakMiddleware(Mock()).process_view(request, view, [], {})

        # THEN not allows endpoint to be accessed (401)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_when_token_is_active_and_has_roles_request_authorizated(self):
        
        # GIVEN token as valid
        KeycloakConnect.is_token_active = Mock(return_value=True)        

        # GIVEN token has roles
        KeycloakConnect.roles_from_token = Mock(return_value=['director'])

        # GIVEN userinfo from fake token
        KeycloakConnect.userinfo = Mock(return_value=self.fake_userinfo)
        
        # GIVEN a View endpoint has existis 'diretor' role on GET method
        view = views.loans

        # GIVEN a fake request
        request = self.factory.get(self.uri)
        request.META['HTTP_AUTHORIZATION'] = 'Bearer token_fake'

        # WHEN middleware is processed
        KeycloakMiddleware(Mock()).process_view(request, view, [], {})

        # THEN allows endpoint and pass token roles and userinfo to request View
        self.assertEqual(['director'], request.roles)
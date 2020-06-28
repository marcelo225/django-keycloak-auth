============================================
Django Keycloak Auth

- [How to use](#how-to-use)
  - [ModelViewSet](#modelviewset)
  - [ViewSet](#viewset)
  - [Install this package to Pypi](#install-this-package-to-pypi)

## What is it?

Django Keycloak Auth is a simple library that authorizes your application's resources using Django Rest Framework.

For review see https://github.com/marcelo225/django-keycloak-auth

## Installation

### Via Pypi Package:

``` $ pip install django-keycloak-auth ```

### Manually

``` $ python setup.py install ```

## Dependencies

* [Python 3](https://www.python.org/)
* [Django Rest Framework](https://www.django-rest-framework.org/)
* [requests](https://requests.readthedocs.io/en/master/)
* [python-jose](https://python-jose.readthedocs.io/en/latest/)

## How to contribute

Please report bugs and feature requests at
https://github.com/marcelo225/django-keycloak-auth/issues

## Licence

The MIT License (MIT)

Copyright (c) 2020 Marcelo Vinícius

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

## Credits

Lead Developer - Marcelo Vinicius

## Usage

1. In settings.py add following Middleware bellow:

```python
MIDDLEWARE = [
    #...
    'keycloak-auth.middleware.KeycloakMiddleware',
    #...
]

#...

# Exempt URIS 
# For example: ['core/banks', 'swagger']
KEYCLOAK_EXEMPT_URIS = []

# Realm public key
KEYCLOAK_REALM_PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
xxxxxxxxxxxxxx
-----END PUBLIC KEY-----"""

KEYCLOAK_CONFIG = {
    'KEYCLOAK_SERVER_URL': 'http://localhost:8080/auth/',
    'KEYCLOAK_REALM': 'TESTE',
    'KEYCLOAK_REALM_PUBLIC_KEY': KEYCLOAK_REALM_PUBLIC_KEY,    
    'KEYCLOAK_REAM_ALGORITHM': 'RS256',
    'KEYCLOAK_CLIENT_ID': 'client-backend',
    'KEYCLOAK_CLIENT_SECRET_KEY': ''    
}

```

# How to use

This is an example how to apply on your Views

## ModelViewSet

```python

class BankViewSet(viewsets.ModelViewSet):

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
```

## ViewSet

```python

class CarViewSet(viewsets.ViewSet):
    keycloak_roles = {
        'GET': ['director', 'judge', 'employee'],
    }
    
    def list(self, request):
        return JsonResponse({"detail": "success"}, status=status.HTTP_200_OK)

```

## Install this package to Pypi

For developers

```bash
# Generate distribuition
$ python setup.py sdist

# Upload package
$ twine upload --repository-url https://upload.pypi.org/legacy/ dist/*

```
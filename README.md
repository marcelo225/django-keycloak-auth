# Django Keycloak Auth

- [Django Keycloak Auth](#django-keycloak-auth)
  - [What is it?](#what-is-it)
  - [Installation](#installation)
    - [Via Pypi Package:](#via-pypi-package)
    - [Manually](#manually)
  - [Dependencies](#dependencies)
  - [Test dependences](#test-dependences)
  - [How to contribute](#how-to-contribute)
  - [Licence](#licence)
  - [Credits](#credits)
  - [Usage](#usage)
- [How to use](#how-to-use)
  - [ModelViewSet](#modelviewset)
  - [ViewSet](#viewset)
  - [APIView](#apiview)
  - [How to run tests for this lib](#how-to-run-tests-for-this-lib)
  - [Install this package to Pypi](#install-this-package-to-pypi)
  - [Install keycloak](#install-keycloak)

## What is it?

Django Keycloak Auth is a simple library that authorizes your application's resources using Django Rest Framework.

This package is used to perform authorization by keycloak roles from JWT token. Both realm roles and client roles are
supported.

For example, the following token indicates that the user has the realm role "manager" and the client
roles "director" and "employer" :

```
...

  "realm_access": {
    "roles": [
      "manager"
    ]
  },
  "resource_access": {
    "first-api": {
      "roles": [
        "director",
        "employer",
      ]
    }
  },
  ...
```

For review see https://github.com/marcelo225/django-keycloak-auth

Package link: https://pypi.org/project/django-keycloak-auth/

## Installation

### Via Pypi Package:

``` $ pip install django-keycloak-auth ```

### Manually

``` $ python setup.py install ```

## Dependencies

* [Python 3](https://www.python.org/)
* [requests](https://requests.readthedocs.io/en/master/)
* [Django](https://www.djangoproject.com/)
* [Django Rest Framework](https://www.django-rest-framework.org/)

## Test dependences

* [unittest](https://docs.python.org/3/library/unittest.html)

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
    'django-keycloak-auth.middleware.KeycloakMiddleware',
    #...
]

#...

# Exempt URIS 
# For example: ['core/banks', 'swagger']
KEYCLOAK_EXEMPT_URIS = []
KEYCLOAK_CONFIG = {
    'KEYCLOAK_SERVER_URL': 'http://localhost:8080/auth',
    'KEYCLOAK_REALM': 'TESTE',
    'KEYCLOAK_CLIENT_ID': 'client-backend',
    'KEYCLOAK_CLIENT_SECRET_KEY': 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
}

```

# How to use

This is an example how to apply on your Views

## ModelViewSet

```python

from rest_framework import viewsets, views
from . import models, serializers
from rest_framework import status
from django.http.response import JsonResponse
from rest_framework.exceptions import PermissionDenied

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
```

## ViewSet

```python

class CarViewSet(viewsets.ViewSet):
    """
    Car endpoint
    This endpoint has not configured keycloak roles. 
    That means all methods will be allowed to access.
    """    
    def list(self, request):
        return JsonResponse({"detail": "success"}, status=status.HTTP_200_OK)        

```

## APIView

```python

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

```

When you don't put **keycloak_roles** attribute in the Views that means all methods authorizations will be allowed.

## How to run tests for this lib

Before everything, you must install VirtualEnv.

```bash
# Install venv in root project folder
$ python3 -m venv env && source env/bin/activate

# Install dependences
$ pip install -r requirements.txt

# Run tests
$ python manage.py test

```

## Install this package to Pypi

`Obs.: Before you update this package, certifies if you'll change the version in [setup.py](setup.py#11) file`

If you interested contribute to developing this project, it was prepared a tiny tutorial to install the environment before you begin:

```bash
# Install venv in root project folder
$ python3 -m venv env && source env/bin/activate

# Update packages
$ python -m pip install --upgrade pip Django djangorestframework requests python-jose twine setuptools wheel

# Generate distribuition -> it's on me for while ;)
$ python setup.py sdist

# Checks if the package has no errors
$ twine check dist/*

# Upload package -> it's on me for while ;)
$ twine upload --repository-url https://upload.pypi.org/legacy/ dist/*

```

## Install keycloak

If you wanna run keycloak docker container:

1. Run following command on terminal:

```bash
# in root project folder
$ docker-compose up
```

2. type http:localhost:8080/ in your web browser 
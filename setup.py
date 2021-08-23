from setuptools import setup, find_packages

# read the contents of your README file
from os import path
this_directory = path.abspath(path.dirname(__file__))
with open(path.join(this_directory, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name="django-keycloak-auth",
    version="0.9.3",
    packages=find_packages(),

    # Project uses reStructuredText, so ensure that the docutils get
    # installed or upgraded on the target machine
    install_requires=[
        "Django",
        "djangorestframework>=3.10.0",
        "requests==2.24.0"
    ],

    # metadata to display on PyPI
    author="Marcelo Vinicius",
    author_email="mr.225@hotmail.com",
    description="Django Keycloak Auth is Python package providing access to the Keycloak API.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    keywords="keycloak django roles authentication authorization",
    url="https://github.com/marcelo225/django-keycloak-auth",
    project_urls={        
        'Funding': 'https://donate.pypi.org',
        'Say Thanks!': 'https://github.com/marcelo225/django-keycloak-auth',
        'Source': 'https://github.com/marcelo225/django-keycloak-auth',
        'Tracker': 'https://github.com/marcelo225/django-keycloak-auth/issues',
    },
    classifiers=[
        "Framework :: Django",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",        
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.5"
    ],
)
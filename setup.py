from setuptools import setup, find_packages

setup(
    name="django-keycloak-auth",
    version="0.2",
    packages=find_packages(),    

    # Project uses reStructuredText, so ensure that the docutils get
    # installed or upgraded on the target machine
    install_requires=[
        "Django>=2.2.13",
        "djangorestframework>=3.10.0",
        "python-jose==3.1.0",
        "requests==2.24.0"
    ],

    # metadata to display on PyPI
    author="Marcelo Vinicius",
    author_email="mr.225@hotmail.com",
    description="Django Rest Framework Keycloak Auth.",
    keywords="keycloak django roles authentication authorization",
    url="https://github.com/marcelo225/keycloak-auth",
    project_urls={
        "Bug Tracker": "https://github.com/marcelo225/django-keycloak-auth/issues/",
        "Documentation": "ttps://github.com/marcelo225/django-keycloak-auth/",
        "Source Code": "https://github.com/marcelo225/keycloak-auth/",
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
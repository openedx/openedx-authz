"""
Test settings for openedx_authz plugin.
"""

import os

from openedx_authz import ROOT_DIRECTORY

# Add Casbin configuration
CASBIN_MODEL = os.path.join(ROOT_DIRECTORY, "engine", "config", "model.conf")
# Redis host and port are temporarily loaded here for the MVP
REDIS_HOST = "redis"
REDIS_PORT = 6379
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": "default.db",
        "USER": "",
        "PASSWORD": "",
        "HOST": "",
        "PORT": "",
    }
}

INSTALLED_APPS = (
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.messages",
    "django.contrib.sessions",
    "openedx_authz.engine.apps.CasbinAdapterConfig",
    "openedx_authz.apps.OpenedxAuthzConfig",
)

MIDDLEWARE = [
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
]

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

SECRET_KEY = "test-secret-key"
CASBIN_WATCHER_ENABLED = False
USE_TZ = True
ROOT_URLCONF = "openedx_authz.urls"

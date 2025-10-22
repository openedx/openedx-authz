"""
Test settings for openedx_authz plugin.
"""

import os

from openedx_authz import ROOT_DIRECTORY


def plugin_settings(settings):  # pylint: disable=unused-argument
    """
    Configure plugin settings for Open edX.
    This function is called by the Open edX plugin system to configure
    the Django settings for this plugin.

    Args:
        settings: The Django settings object
    """


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

USE_TZ = True

ROOT_URLCONF = "openedx_authz.urls"

# Casbin configuration
CASBIN_MODEL = os.path.join(ROOT_DIRECTORY, "engine", "config", "model.conf")
CASBIN_AUTO_LOAD_POLICY_INTERVAL = 0

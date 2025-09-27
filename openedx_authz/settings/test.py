"""
Test settings for openedx_authz plugin.
"""

from os.path import abspath, dirname, join

from openedx_authz import ROOT_DIRECTORY


def root(*args):
    """
    Get the absolute path of the given path relative to the project root.
    """
    return join(abspath(dirname(__file__)), *args)


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
    "casbin_adapter",
    "openedx_authz",
)

LOCALE_PATHS = [
    root("openedx_authz", "conf", "locale"),
]

ROOT_URLCONF = "openedx_authz.urls"

SECRET_KEY = "insecure-secret-key"

MIDDLEWARE = (
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
)

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "APP_DIRS": False,
        "OPTIONS": {
            "context_processors": [
                "django.contrib.auth.context_processors.auth",  # this is required for admin
                "django.contrib.messages.context_processors.messages",  # this is required for admin
            ],
        },
    }
]


CASBIN_MODEL = join(ROOT_DIRECTORY, "engine", "config", "model.conf")
CASBIN_WATCHER_ENABLED = False
REDIS_HOST = "redis"
REDIS_PORT = 6379

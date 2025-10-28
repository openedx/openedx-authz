"""Django app configuration for test stubs."""

from django.apps import AppConfig


class StubsConfig(AppConfig):
    default_auto_field = "django.db.models.AutoField"
    name = "openedx_authz.tests.stubs"
    verbose_name = "Test stubs app"

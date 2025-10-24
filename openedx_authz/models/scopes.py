"""Models for ContentLibrary scopes in the authorization framework.

These models extend the base Scope model to represent content library scopes,
which are used to define permissions and roles related to content libraries
within the Open edX platform.
"""

from django.apps import apps
from django.conf import settings
from django.db import models
from opaque_keys.edx.locator import LibraryLocatorV2

from openedx_authz.models.core import Scope


def get_content_library_model():
    """Return the ContentLibrary model class specified by settings.

    The setting `OPENEDX_AUTHZ_CONTENT_LIBRARY_MODEL` should be an
    app_label.ModelName string (e.g. 'content_libraries.ContentLibrary').
    """
    CONTENT_LIBRARY_MODEL = getattr(
        settings,
        "OPENEDX_AUTHZ_CONTENT_LIBRARY_MODEL",
        "content_libraries.ContentLibrary",
    )
    try:
        app_label, model_name = CONTENT_LIBRARY_MODEL.split(".")
        return apps.get_model(app_label, model_name, require_ready=False)
    except LookupError:
        return None


ContentLibrary = get_content_library_model()


class ContentLibraryScope(Scope):
    """Scope representing a content library in the authorization system.

    .. no_pii:
    """

    NAMESPACE = "lib"

    # Link to the actual course or content library, if applicable. In other cases, this could be null.
    # Piggybacking on the existing ContentLibrary model to keep the ExtendedCasbinRule up to date
    # by deleting the Scope, and thus the ExtendedCasbinRule, when the ContentLibrary is deleted.
    #
    # When content_libraries IS available, the on_delete=CASCADE will still work at the
    # application level through Django's signal handlers.
    # Use a string reference to the external app's model so Django won't try
    # to import it at model import time. The migration already records the
    # dependency on `content_libraries` when the app is present.
    content_library = models.ForeignKey(
        settings.OPENEDX_AUTHZ_CONTENT_LIBRARY_MODEL,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="authz_scopes",
        swappable=True,
    )

    @classmethod
    def get_or_create_for_external_key(cls, scope):
        """Get or create a ContentLibraryScope for the given external key.

        Args:
            scope: ScopeData object with an external_key attribute containing
                a LibraryLocatorV2-compatible string.

        Returns:
            ContentLibraryScope: The Scope instance for the given ContentLibrary
        """
        library_key = LibraryLocatorV2.from_string(scope.external_key)
        content_library = ContentLibrary.objects.get_by_key(library_key)
        scope, _ = cls.objects.get_or_create(content_library=content_library)
        return scope

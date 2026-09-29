"""Models for ContentLibrary scopes in the authorization framework.

These models extend the base Scope model to represent content library scopes,
which are used to define permissions and roles related to content libraries
within the Open edX platform.
"""

from django.apps import apps
from django.conf import settings
from django.db import models

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


def get_course_overview_model():
    """Return the CourseOverview model class specified by settings.

    The setting `OPENEDX_AUTHZ_COURSE_OVERVIEW_MODEL` should be an
    app_label.ModelName string (e.g. 'course_overviews.CourseOverview').
    """
    COURSE_OVERVIEW_MODEL = getattr(
        settings,
        "OPENEDX_AUTHZ_COURSE_OVERVIEW_MODEL",
        "course_overviews.CourseOverview",
    )
    try:
        app_label, model_name = COURSE_OVERVIEW_MODEL.split(".")
        return apps.get_model(app_label, model_name, require_ready=False)
    except LookupError:
        return None


ContentLibrary = get_content_library_model()
CourseOverview = get_course_overview_model()


class ContentLibraryScope(Scope):
    """Scope representing a content library in the authorization system.

    .. no_pii:
    """

    NAMESPACE = "lib"
    LINKED_OBJECT_FIELD = "content_library"

    # Link to the actual content library, if applicable. In other cases, this could be null.
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
    def external_key_for_object(cls, linked_object) -> str:
        """Return the canonical external_key string for a ContentLibrary instance."""
        return str(linked_object.library_key)


class CourseScope(Scope):
    """Scope representing a course in the authorization system.

    .. no_pii:
    """

    NAMESPACE = "course-v1"
    LINKED_OBJECT_FIELD = "course_overview"

    # Link to the actual course, if applicable. In other cases, this could be null.
    # Piggybacking on the existing CourseOverview model to keep the ExtendedCasbinRule up to date
    # by deleting the Scope, and thus the ExtendedCasbinRule, when the CourseOverview is deleted.
    #
    # When course_overviews IS available, the on_delete=CASCADE will still work at the
    # application level through Django's signal handlers.
    # Use a string reference to the external app's model so Django won't try
    # to import it at model import time. The migration already records the
    # dependency on `course_overviews` when the app is present.
    course_overview = models.ForeignKey(
        settings.OPENEDX_AUTHZ_COURSE_OVERVIEW_MODEL,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="authz_scopes",
        swappable=True,
    )

    @classmethod
    def external_key_for_object(cls, linked_object) -> str:
        """Return the canonical external_key string for a CourseOverview instance."""
        return str(linked_object.id)

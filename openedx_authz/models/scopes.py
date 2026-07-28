"""Models for ContentLibrary scopes in the authorization framework.

These models extend the base Scope model to represent content library scopes,
which are used to define permissions and roles related to content libraries
within the Open edX platform.
"""

from django.apps import apps
from django.conf import settings
from django.db import models
from opaque_keys.edx.keys import CourseKey
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
    def get_or_create_for_external_key(cls, scope) -> "ContentLibraryScope":
        """Get or create a ContentLibraryScope for the given external key.

        The backing ContentLibrary need not exist yet (e.g. it may be created
        later as part of an in-progress operation): the scope is created with
        ``content_library=None`` in that case and gets linked up automatically
        once a ContentLibrary with a matching key is saved (see the backfill
        signal receiver in openedx_authz/handlers.py).

        Args:
            scope: ScopeData object with an external_key attribute containing
                a LibraryLocatorV2-compatible string.

        Returns:
            ContentLibraryScope: The Scope instance for the given ContentLibrary,
                or None if the scope is a glob pattern (contains wildcard).
        """
        library_key = LibraryLocatorV2.from_string(scope.external_key)
        try:
            content_library = ContentLibrary.objects.get_by_key(library_key)
        except ContentLibrary.DoesNotExist:
            # The library doesn't exist yet: key the row by its external_key so it can be
            # found and linked up later by the backfill signal in openedx_authz/handlers.py.
            scope, _ = cls.objects.get_or_create(external_key=str(library_key))
            return scope

        # Look up by the FK first (as before this change) so scopes created before the
        # external_key field existed are reused rather than duplicated.
        scope, created = cls.objects.get_or_create(
            content_library=content_library,
            defaults={"external_key": str(library_key)},
        )
        if not created and not scope.external_key:
            scope.external_key = str(library_key)
            scope.save(update_fields=["external_key"])
        return scope


class CourseScope(Scope):
    """Scope representing a course in the authorization system.

    .. no_pii:
    """

    NAMESPACE = "course-v1"

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
    def get_or_create_for_external_key(cls, scope) -> "CourseScope":
        """Get or create a CourseScope for the given external key.

        The backing CourseOverview need not exist yet (e.g. during a course
        rerun, the destination course id is known before the course is
        cloned): the scope is created with ``course_overview=None`` in that
        case and gets linked up automatically once a CourseOverview with a
        matching id is saved (see the backfill signal receiver in
        openedx_authz/handlers.py).

        Args:
            scope: ScopeData object with an external_key attribute containing
                a CourseKey string.

        Returns:
            CourseScope: The Scope instance for the given CourseOverview,
                or None if the scope is a glob pattern (contains wildcard).
        """
        course_key = CourseKey.from_string(scope.external_key)
        try:
            course_overview = CourseOverview.get_from_id(course_key)
        except CourseOverview.DoesNotExist:
            # The course doesn't exist yet: key the row by its external_key so it can be
            # found and linked up later by the backfill signal in openedx_authz/handlers.py.
            scope, _ = cls.objects.get_or_create(external_key=str(course_key))
            return scope

        # Look up by the FK first (as before this change) so scopes created before the
        # external_key field existed are reused rather than duplicated.
        scope, created = cls.objects.get_or_create(
            course_overview=course_overview,
            defaults={"external_key": str(course_key)},
        )
        if not created and not scope.external_key:
            scope.external_key = str(course_key)
            scope.save(update_fields=["external_key"])
        return scope

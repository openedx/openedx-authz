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
        once a ContentLibrary with a matching key is saved (see link_pending_scope()
        and the backfill signal receiver in openedx_authz/handlers.py).

        Args:
            scope: ScopeData object with an external_key attribute containing
                a LibraryLocatorV2-compatible string.

        Returns:
            ContentLibraryScope: The Scope instance for the given ContentLibrary,
                or None if the scope is a glob pattern (contains wildcard).
        """
        content_library = scope.get_object()
        if content_library is None:
            # The library doesn't exist yet: key the row by its external_key so it can be
            # found and linked up later by link_pending_scope().
            row, _ = cls.objects.get_or_create(external_key=scope.external_key)
            return row

        # Look up by the FK first (as before this change) so scopes created before the
        # external_key field existed are reused rather than duplicated.
        row, created = cls.objects.get_or_create(
            content_library=content_library,
            defaults={"external_key": scope.external_key},
        )
        if not created and not row.external_key:
            row.external_key = scope.external_key
            row.save(update_fields=["external_key"])
        return row

    @classmethod
    def link_pending_scope(cls, content_library) -> None:
        """Link a pending ContentLibraryScope to the ContentLibrary that was just created for it.

        Called from the ContentLibrary post_save signal receiver in openedx_authz/handlers.py
        once a library with a matching external_key shows up.

        Args:
            content_library: The ContentLibrary instance that was just saved.
        """
        cls.objects.filter(
            external_key=str(content_library.library_key), content_library__isnull=True
        ).update(content_library=content_library)


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
        matching id is saved (see link_pending_scope() and the backfill
        signal receiver in openedx_authz/handlers.py).

        Args:
            scope: ScopeData object with an external_key attribute containing
                a CourseKey string.

        Returns:
            CourseScope: The Scope instance for the given CourseOverview,
                or None if the scope is a glob pattern (contains wildcard).
        """
        course_overview = scope.get_object()
        if course_overview is None:
            # The course doesn't exist yet: key the row by its external_key so it can be
            # found and linked up later by link_pending_scope().
            row, _ = cls.objects.get_or_create(external_key=scope.external_key)
            return row

        # Look up by the FK first (as before this change) so scopes created before the
        # external_key field existed are reused rather than duplicated.
        row, created = cls.objects.get_or_create(
            course_overview=course_overview,
            defaults={"external_key": scope.external_key},
        )
        if not created and not row.external_key:
            row.external_key = scope.external_key
            row.save(update_fields=["external_key"])
        return row

    @classmethod
    def link_pending_scope(cls, course_overview) -> None:
        """Link a pending CourseScope to the CourseOverview that was just created for it.

        Called from the CourseOverview post_save signal receiver in openedx_authz/handlers.py
        once a course with a matching external_key shows up.

        Args:
            course_overview: The CourseOverview instance that was just saved.
        """
        cls.objects.filter(
            external_key=str(course_overview.id), course_overview__isnull=True
        ).update(course_overview=course_overview)

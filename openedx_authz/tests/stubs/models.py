"""Stub models for testing ContentLibrary-related functionality.

These models mimic the behavior of the actual models so the models can be
referenced in FK relationships without requiring the full application context.
"""

from django.conf import settings
from django.contrib.auth.models import Group
from django.db import models
from opaque_keys.edx.django.models import CourseKeyField, UsageKeyField
from opaque_keys.edx.keys import CourseKey
from opaque_keys.edx.locator import LibraryLocatorV2


class Organization(models.Model):
    """Stub model representing an organization for testing purposes.

    .. no_pii:
    """

    name = models.CharField(max_length=255)
    short_name = models.CharField(max_length=100)

    def __str__(self):
        return str(self.name)


class ContentLibraryManager(models.Manager):
    """Manager for ContentLibrary model with helper methods."""

    def get_by_key(self, library_key):
        """Get or create a ContentLibrary by its library key.

        Args:
            library_key: The library key to look up.

        Returns:
            ContentLibrary: The library instance.
        """
        if library_key is None:
            raise ValueError("library_key must not be None")
        try:
            key = str(LibraryLocatorV2.from_string(str(library_key)))
        except Exception:  # pylint: disable=broad-exception-caught
            key = str(library_key)
        obj, _ = self.get_or_create(locator=key)
        return obj


class ContentLibrary(models.Model):
    """Stub model representing a content library for testing purposes.

    .. no_pii:
    """

    locator = models.CharField(max_length=255, unique=True, db_index=True)
    title = models.CharField(max_length=255, blank=True, null=True)
    slug = models.SlugField(allow_unicode=True)
    org = models.ForeignKey(Organization, on_delete=models.PROTECT, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    objects = ContentLibraryManager()

    def __str__(self):
        return str(self.locator)


# Legacy permission models for testing purposes
class ContentLibraryPermission(models.Model):
    """Stub model representing legacy content library permissions for testing purposes.

    .. no_pii:
    """

    ADMIN_LEVEL = "admin"
    AUTHOR_LEVEL = "author"
    READ_LEVEL = "read"
    ACCESS_LEVEL_CHOICES = (
        (ADMIN_LEVEL, "Administer users and author content"),
        (AUTHOR_LEVEL, "Author content"),
        (READ_LEVEL, "Read-only"),
    )

    library = models.ForeignKey(ContentLibrary, on_delete=models.CASCADE)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, null=True, blank=True)
    group = models.ForeignKey(Group, on_delete=models.CASCADE, null=True, blank=True)
    access_level = models.CharField(max_length=30, choices=ACCESS_LEVEL_CHOICES)

    def __str__(self):
        who = self.user.username if self.user else self.group.name
        return f"ContentLibraryPermission ({self.access_level} for {who})"


class CourseOverview(models.Model):
    """
    Stub model representing a course overview for testing purposes.

    This model contains basic course metadata such as an ID, display name, and organization.
    It is used to link CourseScope instances to actual courses in the system.

    .. no_pii:
    """

    # Course identification
    id = CourseKeyField(db_index=True, primary_key=True, max_length=255)
    _location = UsageKeyField(max_length=255)
    org = models.TextField(max_length=255, default="outdated_entry")
    display_name = models.TextField(null=True)

    @classmethod
    def get_from_id(cls, course_key):
        """Get a CourseOverview by its course key.

        Args:
            course_key: The course key to look up.

        Returns:
            CourseOverview: The course overview instance.
        """
        if course_key is None:
            raise ValueError("course_key must not be None")
        try:
            key = str(CourseKey.from_string(str(course_key)))
        except Exception:  # pylint: disable=broad-exception-caught
            key = str(course_key)
        obj, _ = cls.objects.get_or_create(id=key)
        return obj

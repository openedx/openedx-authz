"""Stub models for testing ContentLibrary-related functionality.

These models mimic the behavior of the actual models so the models can be
referenced in FK relationships without requiring the full application context.
"""

from django.db import models
from opaque_keys.edx.locator import LibraryLocatorV2


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
    created_at = models.DateTimeField(auto_now_add=True)

    objects = ContentLibraryManager()

    def __str__(self):
        return self.locator

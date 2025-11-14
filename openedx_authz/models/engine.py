"""Models for the authorization engine."""

from uuid import UUID, uuid4

from django.db import models


class PolicyCacheControl(models.Model):
    """Model to control policy cache invalidation.

    This model can be used to trigger cache invalidation for authorization policies
    by changing the version. Whenever this model is updated, the authorization
    engine should invalidate its cached policies.
    """

    version = models.UUIDField(default=uuid4)

    def save(self, *args, **kwargs):
        """Override save to ensure a single instance."""
        self.pk = 1  # Ensure a single instance
        super().save(*args, **kwargs)

    @classmethod
    def get(cls):
        """Get the singleton instance of the model."""
        obj, _ = cls.objects.get_or_create(pk=1)
        return obj

    @classmethod
    def get_version(cls):
        """Get the version for policy cache control.

        Returns:
            UUID: The version of the last update.
        """
        instance = cls.get()
        return instance.version

    @classmethod
    def set_version(cls, version: UUID):
        """Update the cache version.

        This method updates the cache version, which can be used to signal
        that the policy cache should be invalidated.
        """
        instance = cls.get()
        instance.version = version

        instance.save()

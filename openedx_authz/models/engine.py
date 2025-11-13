"""Models for the authorization engine."""

from datetime import datetime

from django.db import models


class PolicyCacheControl(models.Model):
    """Model to control policy cache invalidation.

    This model can be used to trigger cache invalidation for authorization policies
    by updating its timestamp. Whenever this model is updated, the authorization
    engine should invalidate its cached policies.
    """

    last_modified = models.DateTimeField(default=datetime.now)

    def save(self, *args, **kwargs):
        """Override save to update the timestamp."""
        self.pk = 1  # Ensure a single instance
        super().save(*args, **kwargs)

    @classmethod
    def get(cls):
        """Get the singleton instance of the model."""
        obj, _ = cls.objects.get_or_create(pk=1)
        return obj

    @classmethod
    def get_last_modified_timestamp(cls):
        """Get the last modified timestamp for policy cache control.

        Returns:
            float: The timestamp of the last update.
        """
        instance = cls.get()
        return instance.last_modified.timestamp()

    @classmethod
    def set_last_modified_timestamp(cls, timestamp: float):
        """Update the last modified timestamp to the current time.

        This method updates the timestamp, which can be used to signal
        that the policy cache should be invalidated.
        """
        instance = cls.get()
        instance.last_modified = datetime.fromtimestamp(timestamp)

        instance.save()

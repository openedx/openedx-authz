"""
Database models for openedx_authz.
"""

from django.db import models


class Library(models.Model):
    """
    Model representing an OpenedX Library with basic information.
    """

    id = models.CharField(max_length=255, primary_key=True, help_text="Library ID in format lib:ORG:SLUG")
    org = models.CharField(max_length=255, help_text="Organization name")
    slug = models.CharField(max_length=255, help_text="Library slug/identifier")
    title = models.CharField(max_length=255, help_text="Library title")
    description = models.TextField(blank=True, help_text="Library description")

    def save(self, *args, **kwargs):
        """
        Override save method to automatically generate ID from org and slug.
        """
        self.id = f"lib:{self.org}:{self.slug}".replace(" ", "_")
        super().save(*args, **kwargs)

    class Meta:
        verbose_name = "Library"
        verbose_name_plural = "Libraries"
        ordering = ["title"]

    def __str__(self):
        return str(self.title)

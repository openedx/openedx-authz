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
    num_blocks = models.IntegerField(default=0, help_text="Number of blocks in the library")
    version = models.IntegerField(default=0, help_text="Library version")
    allow_public_read = models.BooleanField(default=True, help_text="Allow public read access")
    can_edit_library = models.BooleanField(default=False, help_text="Whether user can edit this library")
    created = models.DateTimeField(null=True, blank=True, help_text="Creation timestamp")
    updated = models.DateTimeField(null=True, blank=True, help_text="Last update timestamp")

    class Meta:
        verbose_name = "Library"
        verbose_name_plural = "Libraries"
        ordering = ["title"]

    def __str__(self):
        return str(self.title)

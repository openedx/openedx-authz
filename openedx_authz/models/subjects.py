"""Models for User subjects in the authorization framework.

These models extend the base Subject model to represent user subjects,
which are used to define permissions and roles related to users
within the Open edX platform.
"""

from typing import ClassVar

from django.apps import apps
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import ImproperlyConfigured
from django.db import models, transaction

from openedx_authz.engine.filter import Filter
from openedx_authz.models.core import Subject

User = get_user_model()


class UserSubject(Subject):
    """Subject representing a user in the authorization system."""

    NAMESPACE = "user"

    # Link to the actual user, if the subject is a user. In other cases, this could be null.
    # Piggybacking on the existing User model to keep the ExtendedCasbinRule up to date
    # by deleting the Subject, and thus the ExtendedCasbinRule, when the User is deleted.
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="authz_subjects",
    )

    @classmethod
    def get_or_create_for_external_key(cls, subject):
        """Get or create a UserSubject for the given external key.

        Args:
            subject_external_key: Username string

        Returns:
            UserSubject: The Subject instance for the given User
        """
        user = User.objects.get(username=subject.external_key)
        subject, created = cls.objects.get_or_create(user=user)
        return subject

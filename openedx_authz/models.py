"""
Database models for the authorization framework.

These models will be used to store additional data about roles and permissions
that are not natively supported by Casbin, so as to avoid modifying the Casbin
schema that focuses on the core authorization logic.

For example, we may want to store metadata about roles, such as a description
or the date it was created.
"""

from django.contrib.auth import get_user_model
from django.db import models, transaction
from opaque_keys.edx.locator import LibraryLocatorV2

from openedx_authz.engine.filter import Filter

try:
    from openedx.core.djangoapps.content_libraries.models import ContentLibrary
except ImportError:
    ContentLibrary = None

User = get_user_model()


class Scope(models.Model):
    """
    Model representing a scope in the authorization system.

    This model can be extended to represent different types of scopes,
    such as courses or content libraries.
    """

    # Link to the actual course or content library, if applicable. In other cases, this could be null.
    # Piggybacking on the existing ContentLibrary model to keep the ExtendedCasbinRule up to date
    # by deleting the Scope, and thus the ExtendedCasbinRule, when the ContentLibrary is deleted.
    content_library = models.ForeignKey(
        ContentLibrary,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="authz_scopes",
    )

    @classmethod
    def get_or_create_scope_for_content_library(cls, scope_external_key: str):
        """Helper method to get or create a Scope for a given ContentLibrary.

        Args:
            scope_external_key: Library key string (e.g., "lib:TestOrg:TestLib")

        Returns:
            Scope: The Scope instance for the given ContentLibrary
        """
        library_key = LibraryLocatorV2.from_string(scope_external_key)
        content_library = ContentLibrary.objects.get_by_key(library_key)
        scope, created = cls.objects.get_or_create(content_library=content_library)
        return scope


class Subject(models.Model):
    """
    Model representing a subject in the authorization system.

    This model can be extended to represent different types of subjects,
    such as users or groups.
    """

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
    def get_or_create_subject_for_user(cls, subject_external_key: str):
        """Helper method to get or create a Subject for a given User.

        Args:
            subject_external_key: Username string

        Returns:
            Subject: The Subject instance for the given User
        """
        user = User.objects.get(username=subject_external_key)
        subject, created = cls.objects.get_or_create(user=user)
        return subject


class ExtendedCasbinRule(models.Model):
    """Extended model for Casbin rules to store additional metadata.

    This model extends the CasbinRule model provided by the casbin_adapter
    package to include additional fields for storing metadata about each rule.
    """

    # Instead of making it 1:1 only with the CasbinRule primary key which we usually don't know, let's
    # make an unique key based on the casbin_rule field which is a concatenation of all the fields
    # in the CasbinRule model. This way, we can easily look up the ExtendedCasbinRule
    # based on a policy line which SHOULD be unique.
    casbin_rule_key = models.CharField(max_length=255, unique=True)
    casbin_rule = models.ForeignKey(
        "casbin_adapter.CasbinRule",
        on_delete=models.CASCADE,
        related_name="extended_rule",
    )

    description = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    metadata = models.JSONField(blank=True, null=True)

    # Scope of the rule. This could be a course, content library, or any other scope type. See Scope model above.
    scope = models.ForeignKey(
        Scope,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="casbin_rules",
    )

    # Subject of the rule. This could be a user, group, or any other subject type. See Subject model above.
    subject = models.ForeignKey(
        Subject,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="casbin_rules",
    )

    class Meta:
        verbose_name = "Extended Casbin Rule"
        verbose_name_plural = "Extended Casbin Rules"

    def create_based_on_policy(
        self,
        subject_external_key: str,
        role_external_key: str,
        scope_external_key: str,
        enforcer,
    ):
        """Helper method to create an ExtendedCasbinRule based on policy components.

        Args:
            subject (str): The subject of the policy (e.g., 'user^john_doe').
            action (str): The action of the policy (e.g., 'read', 'write').
            scope (str): The scope of the policy (e.g., 'course-v1:edX+DemoX+2024_T1').
            role (str): The role associated with the policy (e.g., 'instructor').

        Returns:
            ExtendedCasbinRule: The created ExtendedCasbinRule instance.
        """
        casbin_rule = enforcer.query_policy(
            Filter(
                ptype=["g"],
                v0=[subject_external_key],
                v1=[role_external_key],
                v2=[scope_external_key],
            )
        )

        # Create a unique key for the ExtendedCasbinRule
        casbin_rule_key = f"{casbin_rule.ptype},{casbin_rule.v0},{casbin_rule.v1},{casbin_rule.v2},{casbin_rule.v3}"

        with transaction.atomic():
            extended_rule, created = ExtendedCasbinRule.objects.get_or_create(
                casbin_rule_key=casbin_rule_key,
                defaults={
                    "casbin_rule": casbin_rule,
                    "scope": Scope.get_or_create_scope_for_content_library(
                        scope_external_key
                    ),
                    "subject": Subject.get_or_create_subject_for_user(
                        subject_external_key
                    ),
                },
            )

        return extended_rule

"""Core models for the authorization framework.

These models will be used to store additional data about roles and permissions
that are not natively supported by Casbin, so as to avoid modifying the Casbin
schema that focuses on the core authorization logic.
"""

from typing import ClassVar

from django.db import models, transaction

from openedx_authz.engine.filter import Filter


class BaseRegistryModel(models.Model):
    """Base model that supports automatic subclass registration.

    This model provides a registry mechanism for its subclasses, allowing
    dynamic retrieval of subclasses based on a namespace identifier.

    Subclasses should define a NAMESPACE class attribute (e.g., 'user' for users)
    and implement get_or_create_for_external_key() classmethod.
    """

    _registry: ClassVar[dict[str, type["BaseRegistryModel"]]] = {}
    NAMESPACE: ClassVar[str] = None

    class Meta:
        abstract = True

    @classmethod
    def __init_subclass__(cls, **kwargs):
        """Automatically register subclasses when they're defined."""
        super().__init_subclass__(**kwargs)
        if cls.NAMESPACE:
            cls.get_registry()[cls.NAMESPACE] = cls

    @classmethod
    def get_registry(cls) -> dict[str, type["BaseRegistryModel"]]:
        """Get the registry of subclasses.

        Returns:
            dict: A dictionary mapping namespace strings to subclass types.
        """
        return cls._registry

class ScopeManager(models.Manager):
    """Custom manager for Scope model that handles polymorphic behavior."""

    def get_or_create_for_external_key(self, scope_data):
        """Get or create a Scope instance for the given scope data.

        This method determines the appropriate subclass based on the namespace
        in the scope_data and delegates to that subclass's get_or_create_for_external_key.

        Args:
            scope_data: The scope (ScopeData) object with NAMESPACE class attribute

        Returns:
            Scope: The Scope instance

        Raises:
            ValueError: If the namespace is not registered
        """
        namespace = scope_data.NAMESPACE
        if namespace not in (scope_registry := Scope.get_registry()):
            raise ValueError(f"No Scope subclass registered for namespace '{namespace}'")

        scope_class = scope_registry[namespace]
        return scope_class.get_or_create_for_external_key(scope_data)


class SubjectManager(models.Manager):
    """Custom manager for Subject model that handles polymorphic behavior."""

    def get_or_create_for_external_key(self, subject_data):
        """Get or create a Subject instance for the given subject data.

        This method determines the appropriate subclass based on the namespace
        in the subject_data and delegates to that subclass's get_or_create_for_external_key.

        Args:
            subject_data: The subject (SubjectData) object with NAMESPACE class attribute

        Returns:
            Subject: The Subject instance

        Raises:
            ValueError: If the namespace is not registered
        """
        namespace = subject_data.NAMESPACE
        if namespace not in (subject_registry := Subject.get_registry()):
            raise ValueError(f"No Subject subclass registered for namespace '{namespace}'")

        subject_class = subject_registry[namespace]
        return subject_class.get_or_create_for_external_key(subject_data)


class Scope(BaseRegistryModel):
    """Model representing a scope in the authorization system.

    .. no_pii:

    This model can be extended to represent different types of scopes,
    such as courses or content libraries.

    Subclasses should define a NAMESPACE class attribute (e.g., 'lib' for content libraries)
    and implement get_or_create_for_external_key() classmethod.
    """

    objects = ScopeManager()

    class Meta:
        abstract = False


class Subject(BaseRegistryModel):
    """Model representing a subject in the authorization system.

    .. no_pii:

    This model can be extended to represent different types of subjects,
    such as users or groups.

    Subclasses should define a NAMESPACE class attribute (e.g., 'user' for users)
    and implement get_or_create_for_external_key() classmethod.
    """

    objects = SubjectManager()

    class Meta:
        abstract = False


class ExtendedCasbinRule(models.Model):
    """Extended model for Casbin rules to store additional metadata.

    .. no_pii:

    This model extends the CasbinRule model provided by the casbin_adapter
    package to include additional fields for storing metadata about each rule.
    """

    # OneToOne relationship ensures each CasbinRule has at most one ExtendedCasbinRule.
    # We also maintain a unique key based on the casbin_rule field components for easy lookup
    # based on a policy line (ptype,v0,v1,v2,v3) which should be unique.
    #
    # Note: We use CASCADE here. When CasbinRule is deleted, ExtendedCasbinRule is also deleted.
    # The signal handler in handlers.py ensures the reverse (ExtendedCasbinRule deletion → CasbinRule deletion).
    casbin_rule_key = models.CharField(max_length=255, unique=True)
    casbin_rule = models.OneToOneField(
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

    @classmethod
    def create_based_on_policy(
        cls,
        subject,
        role,
        scope,
        adapter,
    ):
        """Helper method to create an ExtendedCasbinRule based on policy components.

        Args:
            subject: SubjectData object with namespaced_key and external_key
            role: RoleData object with namespaced_key and external_key
            scope: ScopeData object with namespaced_key and external_key
            adapter: The Casbin adapter instance.

        Returns:
            ExtendedCasbinRule: The created ExtendedCasbinRule instance.
        """
        casbin_rule = adapter.query_policy(
            Filter(
                ptype=["g"],
                v0=[subject.namespaced_key],
                v1=[role.namespaced_key],
                v2=[scope.namespaced_key],
            )
        ).first()

        if not casbin_rule:
            return None

        casbin_rule_key = f"{casbin_rule.ptype},{casbin_rule.v0},{casbin_rule.v1},{casbin_rule.v2},{casbin_rule.v3}"

        with transaction.atomic():
            extended_rule, _ = cls.objects.get_or_create(
                casbin_rule_key=casbin_rule_key,
                defaults={
                    "casbin_rule": casbin_rule,
                    "scope": Scope.objects.get_or_create_for_external_key(scope),
                    "subject": Subject.objects.get_or_create_for_external_key(subject),
                },
            )

        return extended_rule

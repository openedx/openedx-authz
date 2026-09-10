"""Core models for the authorization framework.

These models will be used to store additional data about roles and permissions
that are not natively supported by Casbin, so as to avoid modifying the Casbin
schema that focuses on the core authorization logic.
"""

from typing import ClassVar, NamedTuple

from django.db import models, transaction

from openedx_authz.constants import AUTHZ_POLICY_ATTRIBUTES_SEPARATOR
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
        # For glob scopes we don't create a Scope object since
        # they don't represent a specific resource type
        if scope_data.IS_GLOB:
            return None

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

    Subclasses should define a NAMESPACE class attribute (e.g., 'lib' for content libraries),
    a LINKED_OBJECT_FIELD naming their FK to the backing object (e.g. 'content_library'), and
    implement external_key_for_object().
    """

    objects = ScopeManager()

    # Name of the subclass's FK field pointing at its backing object (e.g. "content_library",
    # "course_overview"), used by get_or_create_for_external_key()/link_pending_scope() below
    # to work generically across scope types.
    LINKED_OBJECT_FIELD: ClassVar[str] = None

    # Canonical string form of the scope's key (e.g. a course-v1 course id), set on creation
    # regardless of whether the backing object (CourseOverview, ContentLibrary, ...) exists yet.
    # This is the only way to find a scope back again when its FK to that object is still null
    # so it can be linked up once the object is created (see link_pending_scope() below and the
    # backfill signal receivers in openedx_authz/handlers.py).
    external_key = models.CharField(max_length=255, null=True, blank=True, unique=True)

    class Meta:
        abstract = False

    @classmethod
    def external_key_for_object(cls, linked_object) -> str:
        """Return the canonical external_key string for one of this scope's backing objects.

        Subclasses must override this to match how their ScopeData computes external_key
        (e.g. the course id, or the library key).

        Args:
            linked_object: An instance of the model named by LINKED_OBJECT_FIELD.

        Returns:
            str: The canonical external_key for that instance.
        """
        raise NotImplementedError

    @classmethod
    def get_or_create_for_external_key(cls, scope) -> "Scope":
        """Get or create a scope instance for the given external key.

        The backing object (CourseOverview, ContentLibrary, ...) need not exist yet (e.g.
        during a course rerun, the destination course id is known before the course is
        cloned): the scope is created with its LINKED_OBJECT_FIELD left ``None`` in that
        case, and gets linked up automatically once a matching object is saved (see
        link_pending_scope() below and the backfill signal receivers in
        openedx_authz/handlers.py).

        Args:
            scope: ScopeData object with an external_key attribute.

        Returns:
            Scope: The (possibly newly created) scope instance for this subclass.
        """
        external_key = scope.external_key
        linked_object = scope.get_object()
        if linked_object is None:
            # The object doesn't exist yet: key the row by its external_key so it can be
            # found and linked up later by link_pending_scope().
            scope, _ = cls.objects.get_or_create(external_key=external_key)
            return scope

        # Look up by the FK first (as before the external_key field existed) so scopes
        # created before this change are reused rather than duplicated.
        scope, created = cls.objects.get_or_create(
            **{cls.LINKED_OBJECT_FIELD: linked_object},
            defaults={"external_key": external_key},
        )
        if not created and not scope.external_key:
            scope.external_key = external_key
            scope.save(update_fields=["external_key"])
        return scope

    @classmethod
    def link_pending_scope(cls, linked_object) -> None:
        """Link a pending scope to the object that was just created for it.

        Called from the relevant post_save signal receiver in openedx_authz/handlers.py
        once an object with a matching external_key shows up.

        Args:
            linked_object: The model instance (CourseOverview, ContentLibrary, ...) that
                was just saved.
        """
        cls.objects.filter(
            external_key=cls.external_key_for_object(linked_object),
            **{f"{cls.LINKED_OBJECT_FIELD}__isnull": True},
        ).update(**{cls.LINKED_OBJECT_FIELD: linked_object})


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


class RoleAssignmentAuditQuerySet(models.QuerySet):
    """QuerySet for RoleAssignmentAudit with scope-based filtering."""

    def for_scope_namespace(self, namespace: str) -> "RoleAssignmentAuditQuerySet":
        """Return records whose scope starts with the given namespace prefix.

        Args:
            namespace: The namespace to filter by (e.g. ``'lib'``, ``'course-v1'``).
                Use the NAMESPACE class attribute from the corresponding ScopeData
                subclass (e.g. ``ContentLibraryData.NAMESPACE``).

        Returns:
            Queryset filtered to records matching the scope type.
        """
        return self.filter(scope__startswith=f"{namespace}{AUTHZ_POLICY_ATTRIBUTES_SEPARATOR}")


class RoleAssignmentAudit(models.Model):
    """Model to audit role assignments and unassignments.

    .. no_pii:

    This model captures the history of role assignments and unassignments for subjects
    within specific scopes. It can be used for auditing purposes to track changes in
    role assignments over time.
    """

    objects = RoleAssignmentAuditQuerySet.as_manager()

    class Operations(NamedTuple):
        created: str = "created"
        deleted: str = "deleted"

    OPERATIONS = Operations()

    operation = models.CharField(
        max_length=20,
        choices=[(op, op) for op in OPERATIONS],
    )
    subject = models.CharField(
        max_length=255,
        help_text="Namespaced key of the subject (e.g. 'user^john_doe').",
    )
    role = models.CharField(
        max_length=255,
        help_text="Namespaced key of the role (e.g. 'role^library_admin').",
    )
    scope = models.CharField(
        max_length=255,
        help_text="Namespaced key of the scope (e.g. 'course-v1^course-v1:org+course+run') or glob pattern.",
    )
    actor_id = models.IntegerField(
        null=True,
        blank=True,
        help_text="Database ID of the user who performed the operation. Null for system-initiated actions.",
    )
    timestamp = models.DateTimeField()

    class Meta:
        verbose_name = "Role Assignment Audit"
        verbose_name_plural = "Role Assignment Audits"
        ordering = ["-timestamp"]
        indexes = [
            models.Index(fields=["subject"], name="role_audit_subject_idx"),
            models.Index(fields=["scope"], name="role_audit_scope_idx"),
        ]

    @property
    def subject_display(self) -> str:
        """Subject key without the namespace prefix (e.g. ``john_doe`` for ``user^john_doe``)."""
        return self.subject.split(AUTHZ_POLICY_ATTRIBUTES_SEPARATOR, 1)[-1]

    @property
    def role_display(self) -> str:
        """Role name without the namespace prefix (e.g. ``library_admin`` for ``role^library_admin``)."""
        return self.role.split(AUTHZ_POLICY_ATTRIBUTES_SEPARATOR, 1)[-1]

    @property
    def scope_display(self) -> str:
        """Scope key without the namespace prefix (e.g. ``lib:Org1:lib1`` for ``lib^lib:Org1:lib1``)."""
        return self.scope.split(AUTHZ_POLICY_ATTRIBUTES_SEPARATOR, 1)[-1]

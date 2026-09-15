"""Models for compiled authorization definitions and their sources (ADR 0024).

These tables are the authoritative store of the compiled static schema:
permission categories, permission definitions, role definitions, and the
role-permission grants rendered into Casbin ``p`` rows. Each definition and each
role-permission grant is attributed to one or more contributing sources so the
origin of any role or permission can be queried, so a built-in role and a
module-added grant on that role stay distinguishable, and so a future
application removal can prune only what that application uniquely provided.

Casbin ``p`` rows remain the enforcement representation; these tables are the
definition/provenance record written alongside them in the same transaction.
"""

from __future__ import annotations

from django.db import models

__all__ = [
    "OriginKind",
    "AuthzSchemaSource",
    "AuthzPermissionCategory",
    "AuthzPermissionDefinition",
    "AuthzRoleDefinition",
    "AuthzRolePermission",
    "AuthzCategorySource",
    "AuthzPermissionSource",
    "AuthzRoleSource",
    "AuthzRolePermissionSource",
    "origins_for_role",
    "origins_for_permission",
    "origins_for_category",
    "origin_for_role_permission",
]


class OriginKind(models.TextChoices):
    """Whether a contribution is a base definition or an extension (ADR 0023/0024)."""

    BASE = "base", "Base"
    EXTENSION = "extension", "Extension"


class AuthzSchemaSource(models.Model):
    """A distinct schema contribution, identified by distribution and module.

    .. no_pii:

    Identity is ``(distribution, module)`` — moving a definition between files
    within the same module does not change its source. ``resource_path`` and
    ``content_digest`` are non-identifying and advisory (kept latest-seen for
    diagnostics); change detection relies on diffing compiled definitions.
    """

    distribution = models.CharField(
        max_length=255,
        help_text="Installed distribution that shipped the contribution (e.g. 'openedx-authz').",
    )
    module = models.CharField(
        max_length=255,
        help_text="Python module that owns the schema resource (e.g. 'openedx_authz.authz').",
    )
    distribution_version = models.CharField(max_length=64, blank=True, default="")
    resource_path = models.CharField(
        max_length=255,
        blank=True,
        default="",
        help_text="Latest-seen resource path within the module. Non-identifying.",
    )
    content_digest = models.CharField(max_length=64, blank=True, default="")
    schema_version = models.CharField(max_length=16, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Authz Schema Source"
        verbose_name_plural = "Authz Schema Sources"
        constraints = [
            models.UniqueConstraint(fields=["distribution", "module"], name="authz_source_dist_module_uniq"),
        ]

    @property
    def source_id(self) -> str:
        """Stable identifier, e.g. ``'openedx-authz:openedx_authz/authz'``."""
        return f"{self.distribution}:{self.module.replace('.', '/')}"

    def __str__(self):
        return self.source_id


class AuthzPermissionCategory(models.Model):
    """A display/grouping category for permissions (grants no access).

    .. no_pii:
    """

    category_id = models.CharField(max_length=255, unique=True)
    display_name = models.CharField(max_length=255)
    description = models.TextField(blank=True, default="")
    icon = models.CharField(max_length=128, blank=True, null=True)
    sources = models.ManyToManyField(
        AuthzSchemaSource, through="AuthzCategorySource", related_name="categories"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Authz Permission Category"
        verbose_name_plural = "Authz Permission Categories"

    def __str__(self):
        return self.category_id


class AuthzPermissionDefinition(models.Model):
    """A compiled permission definition.

    .. no_pii:

    The complete permission id is ``namespace.name`` (see :attr:`identifier`).
    """

    namespace = models.CharField(max_length=255)
    name = models.CharField(max_length=255)
    display_name = models.CharField(max_length=255)
    description = models.TextField(blank=True, default="")
    category = models.ForeignKey(
        AuthzPermissionCategory,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="permissions",
    )
    scopes = models.JSONField(default=list)
    icon = models.CharField(max_length=128, blank=True, null=True)
    sources = models.ManyToManyField(
        AuthzSchemaSource, through="AuthzPermissionSource", related_name="permissions"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Authz Permission Definition"
        verbose_name_plural = "Authz Permission Definitions"
        constraints = [
            models.UniqueConstraint(fields=["namespace", "name"], name="authz_permission_ns_name_uniq"),
        ]

    @property
    def identifier(self) -> str:
        """Complete permission id, e.g. ``'courses.view_course'``."""
        return f"{self.namespace}.{self.name}"

    def __str__(self):
        return self.identifier


class AuthzRoleDefinition(models.Model):
    """A compiled role definition.

    .. no_pii:

    ``hidden`` mirrors ADR 0023: a hidden role is excluded from normal role
    discovery/selection but keeps its assignments, permission checks, and
    reserved id.
    """

    role_id = models.CharField(max_length=255, unique=True)
    display_name = models.CharField(max_length=255)
    description = models.TextField(blank=True, default="")
    scopes = models.JSONField(default=list)
    icon = models.CharField(max_length=128, blank=True, null=True)
    hidden = models.BooleanField(default=False)
    sources = models.ManyToManyField(
        AuthzSchemaSource, through="AuthzRoleSource", related_name="roles"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Authz Role Definition"
        verbose_name_plural = "Authz Role Definitions"

    def __str__(self):
        return self.role_id


class AuthzRolePermission(models.Model):
    """A single role-permission-scope grant (one per rendered Casbin ``p`` row).

    .. no_pii:

    This is the atomic unit of attribution: a base grant and a module-added
    grant on the same role are distinct rows with distinct sources.
    """

    role = models.ForeignKey(
        AuthzRoleDefinition, on_delete=models.CASCADE, related_name="role_permissions"
    )
    permission = models.ForeignKey(
        AuthzPermissionDefinition, on_delete=models.CASCADE, related_name="role_permissions"
    )
    scope = models.CharField(
        max_length=255,
        help_text="Scope namespace where the grant applies (e.g. 'course-v1', 'lib').",
    )
    sources = models.ManyToManyField(
        AuthzSchemaSource, through="AuthzRolePermissionSource", related_name="role_permissions"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Authz Role Permission"
        verbose_name_plural = "Authz Role Permissions"
        constraints = [
            models.UniqueConstraint(
                fields=["role", "permission", "scope"], name="authz_role_permission_uniq"
            ),
        ]

    def __str__(self):
        return f"{self.role_id} -> {self.permission_id} @ {self.scope}"


# ---------------------------------------------------------------------------
# Source link (through) models. Each carries origin and priority so the winning
# metadata source is derivable and shared ownership is representable.
# ---------------------------------------------------------------------------


class _BaseSourceLink(models.Model):
    """Common fields for source links.

    .. no_pii:
    """

    source = models.ForeignKey(AuthzSchemaSource, on_delete=models.CASCADE)
    origin_kind = models.CharField(max_length=16, choices=OriginKind.choices, default=OriginKind.BASE)
    priority = models.IntegerField(default=0)

    class Meta:
        abstract = True


class AuthzCategorySource(_BaseSourceLink):
    """Links a category to a contributing source.

    .. no_pii:
    """

    category = models.ForeignKey(AuthzPermissionCategory, on_delete=models.CASCADE)

    class Meta:
        verbose_name = "Authz Category Source"
        verbose_name_plural = "Authz Category Sources"
        constraints = [
            models.UniqueConstraint(fields=["category", "source"], name="authz_category_source_uniq"),
        ]


class AuthzPermissionSource(_BaseSourceLink):
    """Links a permission definition to a contributing source.

    .. no_pii:
    """

    permission = models.ForeignKey(AuthzPermissionDefinition, on_delete=models.CASCADE)

    class Meta:
        verbose_name = "Authz Permission Source"
        verbose_name_plural = "Authz Permission Sources"
        constraints = [
            models.UniqueConstraint(fields=["permission", "source"], name="authz_permission_source_uniq"),
        ]


class AuthzRoleSource(_BaseSourceLink):
    """Links a role definition to a contributing source.

    .. no_pii:
    """

    role = models.ForeignKey(AuthzRoleDefinition, on_delete=models.CASCADE)

    class Meta:
        verbose_name = "Authz Role Source"
        verbose_name_plural = "Authz Role Sources"
        constraints = [
            models.UniqueConstraint(fields=["role", "source"], name="authz_role_source_uniq"),
        ]


class AuthzRolePermissionSource(_BaseSourceLink):
    """Links a role-permission grant to a contributing source.

    .. no_pii:

    This is where the extension case is recorded: a core grant links to the
    core source (``origin_kind=base``) and a module-added grant links to that
    module's source (``origin_kind=extension``).
    """

    role_permission = models.ForeignKey(AuthzRolePermission, on_delete=models.CASCADE)

    class Meta:
        verbose_name = "Authz Role Permission Source"
        verbose_name_plural = "Authz Role Permission Sources"
        constraints = [
            models.UniqueConstraint(
                fields=["role_permission", "source"], name="authz_role_permission_source_uniq"
            ),
        ]


# ---------------------------------------------------------------------------
# Query helpers: given any role or permission, get its origin(s).
# ---------------------------------------------------------------------------


def origins_for_role(role_id: str) -> list[str]:
    """Return the distributions that contribute to a role (base + extensions)."""
    return sorted(
        AuthzSchemaSource.objects.filter(roles__role_id=role_id).values_list("distribution", flat=True).distinct()
    )


def origins_for_permission(identifier: str) -> list[str]:
    """Return the distributions that define a permission, by complete id."""
    namespace, _, name = identifier.partition(".")
    return sorted(
        AuthzSchemaSource.objects.filter(permissions__namespace=namespace, permissions__name=name)
        .values_list("distribution", flat=True)
        .distinct()
    )


def origins_for_category(category_id: str) -> list[str]:
    """Return the distributions that define a category."""
    return sorted(
        AuthzSchemaSource.objects.filter(categories__category_id=category_id)
        .values_list("distribution", flat=True)
        .distinct()
    )


def origin_for_role_permission(role_id: str, permission_identifier: str) -> list[str]:
    """Return the distributions that contribute a specific role-permission grant.

    This distinguishes, for one role, the core-provided grants from a grant a
    module added, even though both live in the same role.
    """
    namespace, _, name = permission_identifier.partition(".")
    return sorted(
        AuthzSchemaSource.objects.filter(
            role_permissions__role__role_id=role_id,
            role_permissions__permission__namespace=namespace,
            role_permissions__permission__name=name,
        )
        .values_list("distribution", flat=True)
        .distinct()
    )

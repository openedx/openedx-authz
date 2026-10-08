"""Role and permission catalog for one or more scope types.

The catalog is read from the authz schema models, the same data the Casbin policy is
rendered from, using a constant number of queries (see ADR 0028).
"""

from collections import defaultdict

from openedx_authz.api.data import DefinitionKind
from openedx_authz.models.schema import (
    AuthzPermissionCategory,
    AuthzPermissionDefinition,
    AuthzRoleDefinition,
    AuthzRolePermission,
)

__all__ = ["get_permission_catalog", "get_category_catalog", "get_role_catalog"]


def get_permission_catalog(scope_types: list[str]) -> list[AuthzPermissionDefinition]:
    """Return the permissions that can be granted in any of the scope types.

    A permission qualifies when any of the scope types is among its supported ``scopes``. Each
    permission is loaded with its category.

    Args:
        scope_types (list[str]): The scope types (e.g., ['course-v1', 'lib']).

    Returns:
        list[AuthzPermissionDefinition]: The matching permissions, ordered by identifier
    """
    return sorted(
        (
            permission
            for permission in AuthzPermissionDefinition.objects.select_related("category")
            if any(scope_type in permission.scopes for scope_type in scope_types)
        ),
        key=lambda permission: permission.identifier,
    )


def get_category_catalog(permissions: list[AuthzPermissionDefinition]) -> list[AuthzPermissionCategory]:
    """Return the distinct categories used by the given permissions.

    Permissions without a category are ignored. No queries are made when the permissions were
    loaded with their category, as :func:`get_permission_catalog` does.

    Args:
        permissions (list[AuthzPermissionDefinition]): The permissions to collect categories
            from, typically the result of :func:`get_permission_catalog`.

    Returns:
        list[AuthzPermissionCategory]: Each category once, ordered by ``category_id``.
    """
    categories = {
        permission.category.category_id: permission.category for permission in permissions if permission.category
    }
    return [categories[category_id] for category_id in sorted(categories)]


def get_role_catalog(scope_types: list[str]) -> list[dict]:
    """Return the roles that can be assigned in any of the scope types, with their grants in them.

    A role is included when it has at least one permission grant in any of the scope types and is
    not hidden. Roles and their grants are read only from the stored schema definitions, never
    from the Casbin policy, so a role without a stored definition is not listed. Hidden roles are
    never included, even if they are assigned to users.

    Args:
        scope_types (list[str]): The scope types (e.g., ['course-v1', 'lib']).

    Returns:
        list[dict]: One item per role, ordered by role identifier, with the keys:

        - ``role``: The role identifier.
        - ``display_name``: Human-readable name.
        - ``description``: Role description; empty when unknown.
        - ``icon``: Paragon icon name, or ``None``.
        - ``definition_kind``: The :class:`DefinitionKind` value of the role.
        - ``permissions``: Sorted identifiers of the permissions the role grants in the scope types.
    """
    grants = defaultdict(set)
    for role_id, namespace, name in AuthzRolePermission.objects.filter(
        scope__in=scope_types, role__hidden=False
    ).values_list("role__role_id", "permission__namespace", "permission__name"):
        grants[role_id].add(f"{namespace}.{name}")

    definitions = AuthzRoleDefinition.objects.filter(role_id__in=grants)
    return [
        {
            "role": definition.role_id,
            "display_name": definition.display_name,
            "description": definition.description,
            "icon": definition.icon,
            "definition_kind": DefinitionKind.STATIC.value,
            "permissions": sorted(grants[definition.role_id]),
        }
        for definition in definitions.order_by("role_id")
    ]

"""Role and permission catalog for a scope namespace.

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


def get_permission_catalog(namespace: str) -> list[AuthzPermissionDefinition]:
    """Return the permissions that can be granted in a scope namespace.

    A permission qualifies when the namespace is among its supported ``scopes``. Each permission
    is loaded with its category.

    Args:
        namespace (str): The scope namespace (e.g., 'course-v1', 'lib').

    Returns:
        list[AuthzPermissionDefinition]: The matching permissions, ordered by identifier
    """
    return sorted(
        (
            permission
            for permission in AuthzPermissionDefinition.objects.select_related("category")
            if namespace in permission.scopes
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


def get_role_catalog(namespace: str) -> list[dict]:
    """Return the roles that can be assigned in a scope namespace, with their grants in it.

    A role is included when it has at least one permission grant in the namespace and is not
    hidden. Roles and their grants are read only from the stored schema definitions, never from
    the Casbin policy. Hidden roles are never included, even if they are assigned to users.

    Args:
        namespace (str): The scope namespace (e.g., 'course-v1', 'lib').

    Returns:
        list[dict]: One item per role, ordered by role identifier, with the keys:

        - ``role``: The role identifier.
        - ``display_name``: Human-readable name.
        - ``description``: Role description; empty when unknown.
        - ``icon``: Paragon icon name, or ``None``.
        - ``definition_kind``: The :class:`DefinitionKind` value of the role.
        - ``permissions``: Sorted identifiers of the permissions the role grants in the namespace.
    """
    grants = defaultdict(set)
    for role_id, namespace_, name in AuthzRolePermission.objects.filter(scope=namespace).values_list(
        "role__role_id", "permission__namespace", "permission__name"
    ):
        grants[role_id].add(f"{namespace_}.{name}")

    definitions = {role.role_id: role for role in AuthzRoleDefinition.objects.all()}
    items = {}
    for role_id, permission_ids in grants.items():
        definition = definitions[role_id]
        if definition.hidden:
            continue
        items[role_id] = {
            "role": role_id,
            "display_name": definition.display_name,
            "description": definition.description,
            "icon": definition.icon,
            "definition_kind": DefinitionKind.STATIC.value,
            "permissions": sorted(permission_ids),
        }

    return [items[role_id] for role_id in sorted(items)]

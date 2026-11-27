"""Role and permission catalog for one or more scope types.

The catalog is read from the authz schema models, the same data the Casbin policy is
rendered from, using a constant number of queries (see ADR 0028).
"""

from openedx_authz.api.exceptions import RoleNotFoundError
from openedx_authz.constants import DefinitionKind
from openedx_authz.models.schema import (
    AuthzPermissionCategory,
    AuthzPermissionDefinition,
    AuthzRoleDefinition,
    AuthzRoleDefinitionQuerySet,
)

__all__ = ["get_permission_catalog", "get_category_catalog", "get_role_catalog", "get_role_catalog_entry"]


def get_permission_catalog(scope_types: list[str]) -> list[AuthzPermissionDefinition]:
    """Return the permissions that can be granted in any of the scope types.

    A permission qualifies when any of the scope types is among its supported ``scopes`` and it is
    visible: neither the permission nor its category is hidden. Each permission is loaded with its
    category.

    Args:
        scope_types (list[str]): The scope types (e.g., ['course-v1', 'lib']).

    Returns:
        list[AuthzPermissionDefinition]: The matching permissions, ordered by namespace and name
    """
    return list(
        AuthzPermissionDefinition.objects.visible()
        .supporting_scope_types(scope_types)
        .select_related("category")
        .order_by("namespace", "name")
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
    not hidden. Hidden permissions, and permissions in hidden categories, are left out of
    ``permissions``. Roles and their grants are read only from the stored schema definitions, never
    from the Casbin policy, so a role without a stored definition is not listed. Hidden roles are
    never included, even if they are assigned to users. A custom role left with no permissions is
    still listed by its stored resource type, with empty ``permissions``.

    Args:
        scope_types (list[str]): The scope types (e.g., ['course-v1', 'lib']).

    Returns:
        list[dict]: One item per role, ordered by role identifier, with the keys:

        - ``role``: The role identifier.
        - ``display_name``: Human-readable name.
        - ``description``: Role description; empty when unknown.
        - ``icon``: Paragon icon name, or ``None``.
        - ``definition_kind``: The :class:`DefinitionKind` value of the role.
        - ``permissions``: Sorted identifiers of the permissions the role grants in the scope types,
          without hidden ones.
        - ``scope_types``: Sorted scope types, among the requested ones, in the role's ``scopes``. Grants
          are rendered from them, so this does not depend on which permissions are hidden.
        - ``updated_at``: When a custom role last changed. ``None`` for static roles, which have no
          meaningful edit date.
    """
    roles = _roles_in_scope_types(AuthzRoleDefinition.objects.visible(), scope_types)
    return [_build_role_entry(role, scope_types) for role in roles.order_by("role_id")]


def get_role_catalog_entry(role_id: str) -> dict:
    """Return the catalog entry of one visible role, in every scope type the role supports.

    Args:
        role_id (str): The role identifier.

    Returns:
        dict: The role with the keys described in :func:`get_role_catalog`.

    Raises:
        RoleNotFoundError: If the role does not exist, is hidden or was removed, or is a static role
            with no grants, which the catalog leaves out as well.
    """
    roles = AuthzRoleDefinition.objects.visible().filter(role_id=role_id)
    scope_types = roles.values_list("scopes", flat=True).first()
    role = None if scope_types is None else _roles_in_scope_types(roles, scope_types).first()
    if role is None:
        raise RoleNotFoundError(f"There is no role {role_id!r}.")
    return _build_role_entry(role, scope_types)


def _roles_in_scope_types(roles: AuthzRoleDefinitionQuerySet, scope_types: list[str]) -> AuthzRoleDefinitionQuerySet:
    """Return the roles the catalog lists in the scope types, with their visible grants loaded.

    A role is listed when it has a grant in the scope types. A custom role left with no grants is
    matched by its resource type as well, so an administrator can still add permissions to it or
    remove it (ADR 0035, ADR 0036).
    """
    listed = roles.with_grants_in_scope_types(scope_types) | roles.user_defined_in_scope_types(scope_types)
    return listed.prefetch_grants_in_scope_types(scope_types)


def _build_role_entry(role: AuthzRoleDefinition, scope_types: list[str]) -> dict:
    """Return the catalog entry of a role loaded by :func:`_roles_in_scope_types`."""
    is_custom = role.definition_kind == DefinitionKind.USER_DEFINED.value
    return {
        "role": role.role_id,
        # TODO: translate ``display_name`` (and ``description``) here when runtime schema
        # translation lands (ADR 0020). RoleListView searches and sorts these dicts before
        # serializing, so translating in the serializer instead would make search and sort
        # match the English names while the user sees the translated ones. In the same change,
        # switch ``filter_roles`` and ``_role_sort_value`` in ``rest_api/utils.py`` from
        # ``lower()`` to ``casefold()``, so translated names compare without case (e.g. "ß" vs "SS").
        "display_name": role.display_name,
        "description": role.description,
        "icon": role.icon,
        "definition_kind": role.definition_kind,
        "permissions": sorted({grant.permission.identifier for grant in role.grants}),
        "scope_types": sorted(set(role.scopes) & set(scope_types)),
        "updated_at": role.updated_at if is_custom else None,
    }

"""Create, edit and remove custom roles (ADR 0035).

A custom role is stored like a static one: a row in the role definition table, one row per granted
permission, and the matching Casbin ``p`` rows. Every change updates those three together in one
transaction, under the same lock as schema deployments, and takes effect for every holder of the
role as soon as the policy cache is invalidated.

This module only changes definitions. Who may call it, the REST contract and the audit trail of
role changes are decided elsewhere.
"""

import re
import unicodedata
from collections.abc import Collection, Iterator, Sequence
from contextlib import contextmanager

from django.utils import timezone

from openedx_authz.api.data import RoleData
from openedx_authz.api.exceptions import (
    CustomRoleError,
    CustomRoleHasAssignmentsError,
    CustomRoleNameTakenError,
    CustomRoleNotFoundError,
    InvalidCustomRoleError,
    StaticRoleError,
)
from openedx_authz.api.roles import get_role_assignments, unassign_role_from_subject_in_scope
from openedx_authz.constants import CUSTOM_ROLE_ID_MAX_LENGTH, CUSTOM_ROLE_ID_PREFIX, DefinitionKind
from openedx_authz.engine.enforcer import AuthzEnforcer
from openedx_authz.engine.policy import PolicyRow, PolicyStore, serialized_policy_update
from openedx_authz.models.schema import AuthzPermissionDefinition, AuthzRoleDefinition, AuthzRolePermission

__all__ = [
    "create_custom_role",
    "remove_custom_role",
    "update_custom_role",
]

FALLBACK_ROLE_SLUG = "role"
DISPLAY_NAME_MAX_LENGTH = AuthzRoleDefinition._meta.get_field("display_name").max_length


def slugify_role_name(display_name: str) -> str:
    """Convert a display name to the lowercase letters, digits and underscores of a role ID.

    Accents are dropped by decomposing the name and discarding what is not ASCII, so no
    transliteration dependency is needed. A name written only in a non-Latin script gives an
    empty result.

    Args:
        display_name (str): The name as the administrator entered it.

    Returns:
        str: The converted name, without leading or trailing underscores.
    """
    ascii_name = unicodedata.normalize("NFKD", display_name).encode("ascii", "ignore").decode("ascii")
    return re.sub(r"[^a-z0-9]+", "_", ascii_name.lower()).strip("_")


def build_custom_role_id(display_name: str, taken_ids: Collection[str]) -> str:
    """Return the first free custom role ID for a display name.

    The ID is the reserved prefix followed by the converted name. When it is taken, a numeric
    suffix starting at 2 is added. The converted name is cut so the whole ID, suffix included,
    fits the maximum length, and underscores left at the end of the cut are dropped.

    Args:
        display_name (str): The name as the administrator entered it.
        taken_ids (Collection[str]): Every ID that cannot be reused, including removed roles.

    Returns:
        str: An ID that is not in ``taken_ids``.
    """
    base = f"{CUSTOM_ROLE_ID_PREFIX}{slugify_role_name(display_name) or FALLBACK_ROLE_SLUG}"
    candidate = base[:CUSTOM_ROLE_ID_MAX_LENGTH].rstrip("_")
    number = 1
    while candidate in taken_ids:
        number += 1
        suffix = f"_{number}"
        candidate = f"{base[: CUSTOM_ROLE_ID_MAX_LENGTH - len(suffix)].rstrip('_')}{suffix}"
    return candidate


def create_custom_role(
    display_name: str,
    description: str,
    scope_type: str,
    permissions: Sequence[str],
) -> AuthzRoleDefinition:
    """Create a custom role that grants the given permissions in one scope type.

    Args:
        display_name (str): The name shown to administrators. It is stored without surrounding
            whitespace, so names that differ only in it count as the same name.
        description (str): Free text, which may be empty.
        scope_type (str): The resource type the role applies to (e.g., ``course-v1`` or ``lib``).
        permissions (Sequence[str]): Complete IDs of the permissions the role grants. Each must
            exist and support the scope type.

    Returns:
        AuthzRoleDefinition: The new role, with an ID derived from the display name.

    Raises:
        InvalidCustomRoleError: If an argument has the wrong type, the name is blank or too long,
            or the permissions are empty, unknown, hidden or do not support the scope type.
        CustomRoleNameTakenError: If another role that has not been removed uses the name.
    """
    _validate_text("display name", display_name)
    _validate_text("description", description)
    _validate_text("scope type", scope_type)
    display_name = display_name.strip()
    _validate_display_name(display_name)
    with _writing_custom_roles() as policy_store:
        _check_display_name_is_free(display_name)
        resolved = _resolve_permissions(permissions, [scope_type])
        role = AuthzRoleDefinition.objects.create(
            role_id=build_custom_role_id(display_name, _taken_role_ids()),
            display_name=display_name,
            description=description,
            scopes=[scope_type],
            definition_kind=DefinitionKind.USER_DEFINED.value,
        )
        _add_grants(policy_store, role, resolved)
    return role


def update_custom_role(
    role_id: str,
    *,
    description: str | None = None,
    permissions: Sequence[str] | None = None,
) -> AuthzRoleDefinition:
    """Change the description or the permissions of a custom role.

    The role ID, name and scope type stay as they were. Permissions that are added or dropped
    reach every holder of the role right away. Any edit, including a permissions-only one, sets
    the role's ``updated_at``.

    Args:
        role_id (str): The ID of the custom role.
        description (str | None): The new description, or ``None`` to keep the current one.
        permissions (Sequence[str] | None): The complete new list of permission IDs, or ``None``
            to keep the current ones.

    Returns:
        AuthzRoleDefinition: The updated role.

    Raises:
        CustomRoleNotFoundError: If there is no such custom role, or it was removed.
        StaticRoleError: If the role is a static role.
        InvalidCustomRoleError: If nothing is given to change, an argument has the wrong type, or
            the permissions are empty, unknown, hidden or unsupported by the role.
    """
    if description is None and permissions is None:
        raise InvalidCustomRoleError("Give a description or permissions to change.")
    if description is not None:
        _validate_text("description", description)
    with _writing_custom_roles() as policy_store:
        role = _get_active_custom_role(role_id)
        if permissions is not None:
            _replace_grants(policy_store, role, _resolve_permissions(permissions, role.scopes))
        if description is not None:
            role.description = description
        role.save(update_fields=["description", "updated_at"])
    return role


def remove_custom_role(role_id: str, *, delete_assignments: bool = False) -> None:
    """Remove a custom role, its grants and its assignments.

    The role definition stays in the table, marked as removed, so its ID is never reused and
    audit records can still name it. The role no longer grants any access.

    Args:
        role_id (str): The ID of the custom role.
        delete_assignments (bool): Must be true to remove a role that still has assignments.

    Raises:
        CustomRoleNotFoundError: If there is no such custom role, or it was removed already.
        StaticRoleError: If the role is a static role.
        CustomRoleHasAssignmentsError: If the role has assignments and ``delete_assignments`` is false.
    """
    with _writing_custom_roles() as policy_store:
        role = _get_active_custom_role(role_id)
        assignments = get_role_assignments(role=RoleData(external_key=role_id))
        if assignments and not delete_assignments:
            raise CustomRoleHasAssignmentsError(role_id, len(assignments))
        for assignment in assignments:
            unassign_role_from_subject_in_scope(assignment.subject, assignment.roles[0], assignment.scope)
        _remove_grants(policy_store, role, list(role.role_permissions.select_related("permission")))
        role.removed_at = timezone.now()
        role.save(update_fields=["removed_at", "updated_at"])


@contextmanager
def _writing_custom_roles() -> Iterator[PolicyStore]:
    """Run a custom role change under the policy write lock and publish it on success.

    Yields the policy store the change writes its ``p`` rows through.

    The cache is invalidated inside the transaction, so the new version commits together with the
    rows. If the change fails for any other reason than an invalid request, the in-memory policy
    may already hold rows the database rolled back, so the cache is invalidated again after the
    rollback to force a reload (ADR 0018 §5).
    """
    policy_store = PolicyStore()
    try:
        with serialized_policy_update(policy_store):
            yield policy_store
            AuthzEnforcer.invalidate_policy_cache()
    except CustomRoleError:
        raise
    except Exception:
        AuthzEnforcer.invalidate_policy_cache()
        raise


def _validate_text(field: str, value: object) -> None:
    """Reject a value that is not a string, so a missing field is reported instead of failing in the database."""
    if not isinstance(value, str):
        raise InvalidCustomRoleError(f"The {field} must be a string.")


def _validate_permission_ids(permission_ids: object) -> None:
    """Reject anything but a sequence of permission ID strings.

    A single string is rejected too, since iterating it would treat each character as an ID.
    """
    if (
        isinstance(permission_ids, str)
        or not isinstance(permission_ids, Sequence)
        or not all(isinstance(permission_id, str) for permission_id in permission_ids)
    ):
        raise InvalidCustomRoleError("The permissions must be a list of permission ID strings.")


def _validate_display_name(display_name: str) -> None:
    """Reject a display name that is blank or longer than its column."""
    if not display_name:
        raise InvalidCustomRoleError("The display name cannot be blank.")
    if len(display_name) > DISPLAY_NAME_MAX_LENGTH:
        raise InvalidCustomRoleError(f"The display name cannot be longer than {DISPLAY_NAME_MAX_LENGTH} characters.")


def _check_display_name_is_free(display_name: str) -> None:
    """Reject a display name used by another role that has not been removed, static or custom.

    Names are compared ignoring case. A static role is compared by its stored name, not its
    translation.
    """
    if AuthzRoleDefinition.objects.active().filter(display_name__iexact=display_name).exists():
        raise CustomRoleNameTakenError(f"A role named {display_name!r} already exists.")


def _taken_role_ids() -> set[str]:
    """Return every custom role ID in use, including removed roles, whose IDs stay reserved."""
    return set(AuthzRoleDefinition.objects.user_defined().values_list("role_id", flat=True))


def _get_active_custom_role(role_id: str) -> AuthzRoleDefinition:
    """Return a custom role that has not been removed, or explain why there is none."""
    role = AuthzRoleDefinition.objects.filter(role_id=role_id).first()
    if role is None or role.removed_at is not None:
        raise CustomRoleNotFoundError(f"There is no custom role {role_id!r}.")
    if role.definition_kind != DefinitionKind.USER_DEFINED.value:
        raise StaticRoleError(f"Role {role_id!r} is a static role and is read-only.")
    return role


def _resolve_permissions(permission_ids: Sequence[str], scope_types: Sequence[str]) -> list[AuthzPermissionDefinition]:
    """Return the permission definitions for the IDs, if each can be granted by a custom role.

    Each permission must exist, be visible and support every scope type. Hidden permissions, and
    permissions in hidden categories, are reserved for static roles. Duplicate IDs are ignored and
    the order of the first occurrence is kept.
    """
    _validate_permission_ids(permission_ids)
    requested = list(dict.fromkeys(permission_ids))
    if not requested:
        raise InvalidCustomRoleError("A custom role must grant at least one permission.")

    found = {
        permission.identifier: permission
        for permission in AuthzPermissionDefinition.objects.with_identifiers(requested)
    }
    unknown = [pid for pid in requested if pid not in found]
    if unknown:
        raise InvalidCustomRoleError(f"Unknown permissions: {', '.join(unknown)}.")

    visible = {
        permission.identifier for permission in AuthzPermissionDefinition.objects.with_identifiers(requested).visible()
    }
    hidden = [pid for pid in requested if pid not in visible]
    if hidden:
        raise InvalidCustomRoleError(f"Hidden permissions cannot be granted by a custom role: {', '.join(hidden)}.")

    unsupported = [pid for pid in requested if not set(scope_types) <= set(found[pid].scopes)]
    if unsupported:
        raise InvalidCustomRoleError(
            f"Permissions that do not support {', '.join(scope_types)}: {', '.join(unsupported)}."
        )
    return [found[pid] for pid in requested]


def _replace_grants(
    policy_store: PolicyStore, role: AuthzRoleDefinition, permissions: Sequence[AuthzPermissionDefinition]
) -> None:
    """Make the role grant exactly the given permissions, changing only what differs."""
    current = list(role.role_permissions.select_related("permission"))
    wanted = {permission.pk for permission in permissions}
    granted = {grant.permission_id for grant in current}
    _remove_grants(policy_store, role, [grant for grant in current if grant.permission_id not in wanted])
    _add_grants(policy_store, role, [permission for permission in permissions if permission.pk not in granted])


def _add_grants(
    policy_store: PolicyStore, role: AuthzRoleDefinition, permissions: Sequence[AuthzPermissionDefinition]
) -> None:
    """Store a grant and its ``p`` row for each permission in each of the role's scope types."""
    for permission in permissions:
        for scope_type in role.scopes:
            AuthzRolePermission.objects.create(role=role, permission=permission, scope=scope_type)
            policy_store.add_policy_row(PolicyRow.from_grant(role.role_id, permission.identifier, scope_type))


def _remove_grants(policy_store: PolicyStore, role: AuthzRoleDefinition, grants: Sequence[AuthzRolePermission]) -> None:
    """Delete the grants and their ``p`` rows."""
    for grant in grants:
        policy_store.remove_policy_row(PolicyRow.from_grant(role.role_id, grant.permission.identifier, grant.scope))
        grant.delete()

"""Static definition objects for the authz schema pipeline.

These dataclasses describe the author-facing schema vocabulary (ADR 0017 /
``docs/references/authorization-schema.rst``): permission categories,
permissions, static roles, and role extensions. Identifiers match
``[a-z][a-z0-9_]*``, permission IDs join ``namespace`` and ``name`` with a
period, and the internal Casbin forms (``act^...``, ``role^...``) never appear
here.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PermissionCategory:
    """A display/grouping category for permissions. Grants no access."""

    id: str
    display_name: str
    description: str
    icon: str | None = None


@dataclass(frozen=True)
class PermissionDefinition:
    """A single permission.

    The complete permission ID (used by role definitions, extensions, app
    checks, and API responses) is :attr:`identifier`.
    """

    namespace: str
    name: str
    display_name: str
    description: str
    category: str
    scopes: tuple[str, ...]
    icon: str | None = None

    @property
    def identifier(self) -> str:
        """Complete permission ID, e.g. ``"courses.view_course"``."""
        return f"{self.namespace}.{self.name}"


@dataclass(frozen=True)
class RoleDefinition:
    """A static role listing every permission assigned to it.

    ``hidden`` mirrors ADR 0023: a hidden role is excluded from normal role
    discovery/selection but keeps its assignments, permission checks, and
    reserved ID.
    """

    id: str
    display_name: str
    description: str
    scopes: tuple[str, ...]
    permissions: tuple[str, ...]
    icon: str | None = None
    hidden: bool = False


@dataclass(frozen=True)
class RoleExtension:
    """A change to an existing static role (ADR 0023).

    Only the included fields change; ``None``/empty means "leave unchanged".
    An extension can never change the role ID or replace the whole definition.
    ``hidden`` is tri-state: ``None`` leaves the current value untouched.
    """

    role: str
    add_permissions: tuple[str, ...] = ()
    remove_permissions: tuple[str, ...] = ()
    display_name: str | None = None
    description: str | None = None
    icon: str | None = None
    hidden: bool | None = None

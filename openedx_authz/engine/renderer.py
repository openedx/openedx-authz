"""Render compiled definitions to Casbin rows (ADR 0018 §1, §5).

This is the Casbin-aware edge of the schema pipeline. It implements the
``render`` lifecycle step:

* ``render`` builds the Casbin ``p`` rows for a :class:`CompiledSchema` in
  memory, without touching the database.

Key semantics:
    * Definition rows only: ``render`` emits ``p`` rows and never ``g``
      (assignments) or ``g2`` (legacy action inheritance), so data owned by
      other services is out of its reach by construction (ADR 0018 §3).
    * Namespacing happens here, at the boundary: schema objects carry bare
      identifiers, and the internal Casbin form (``role^``, ``act^``,
      ``<scope>^*``) is applied on the way out.
    * Deterministic output: rows are emitted in sorted order, so the rendered
      set can be compared against a stored policy without spurious diffs.

``render`` is pure — it imports nothing from Casbin or Django and performs no
database access.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from openedx_authz.data import AUTHZ_POLICY_ATTRIBUTES_SEPARATOR as SEP
from openedx_authz.engine.schema.types import CompiledSchema, RoleDefinition

# Namespace prefixes for the internal Casbin form (schema objects never carry them).
ROLE_PREFIX = "role"
ACTION_PREFIX = "act"
SCOPE_WILDCARD = "*"
ALLOW = "allow"
POLICY_PTYPE = "p"


@dataclass(frozen=True)
class PolicyRow:
    """A single Casbin ``p`` row rendered from a role-permission pair.

    Fields follow the ``p`` shape: subject (role), action (permission), scope
    pattern, effect. Namespacing to the internal Casbin form (``role^``,
    ``act^``, ``<scope>^*``) happens here, at the boundary — schema objects
    never carry those prefixes.
    """

    ptype: str  # always "p" for rendered definition rows
    subject: str
    action: str
    scope: str
    effect: str

    def as_policy(self) -> list[str]:
        """Return the enforcer arg form: ``[subject, action, scope, effect]``."""
        return [self.subject, self.action, self.scope, self.effect]

    @classmethod
    def from_policy(cls, values: list[str]) -> "PolicyRow":
        """Build from a stored ``p`` row (``[subject, action, scope, effect]``)."""
        subject, action, scope, effect = (list(values) + ["", "", "", ""])[:4]
        return cls(POLICY_PTYPE, subject, action, scope, effect)


@dataclass
class RenderedPolicy:
    """The full set of ``p`` rows for a compiled schema (no DB access)."""

    rows: list[PolicyRow] = field(default_factory=list)


def policy_row(role_id: str, permission_id: str, scope: str) -> PolicyRow:
    """Build the Casbin ``p`` row for one ``(role, permission, scope)`` grant.

    The single place the internal namespacing is applied, so every producer and
    consumer of a rendered row agrees on its exact shape. A drift between two
    such places would silently stop a later comparison against the stored
    policy from matching anything.
    """
    return PolicyRow(
        ptype=POLICY_PTYPE,
        subject=f"{ROLE_PREFIX}{SEP}{role_id}",
        action=f"{ACTION_PREFIX}{SEP}{permission_id}",
        scope=f"{scope}{SEP}{SCOPE_WILDCARD}",
        effect=ALLOW,
    )


class PolicyRenderer:
    """Turns a :class:`CompiledSchema` into Casbin ``p`` rows in memory."""

    def render(self, schema: CompiledSchema) -> RenderedPolicy:
        """Produce one ``p`` row per (role, permission, supported scope).

        Emits definition (``p``) rows only — never ``g`` (assignments) or ``g2``
        (action inheritance). Applies the internal Casbin namespacing here.
        Performs no database access. Output order is deterministic.
        """
        rows: list[PolicyRow] = []
        for role_id in sorted(schema.roles):
            role: RoleDefinition = schema.roles[role_id].definition
            for scope in sorted(role.scopes):
                for permission in sorted(role.permissions):
                    rows.append(policy_row(role.id, permission, scope))
        return RenderedPolicy(rows=rows)

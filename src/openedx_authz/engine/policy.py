"""Domain-typed policy rows and the Casbin-facing policy store (ADR 0018).

This module is the boundary between the schema-apply pipeline and Casbin. It
holds two kinds of thing:

* :class:`PolicyRow` and :class:`GroupingRow` — frozen, hashable value objects
  that model a single Casbin ``p`` (definition) row and ``g`` (assignment) row
  respectively. They carry the internal Casbin namespacing (``role^``, ``act^``,
  ``<scope>^*``) and own the translation to and from the raw ``list[str]`` form
  Casbin stores, delegating the field layout to the shared
  :class:`~openedx_authz.data.PolicyIndex` / :class:`~openedx_authz.data.GroupingPolicyIndex`.

* :class:`PolicyStore` — a thin wrapper over a Casbin enforcer that exposes only
  the policy operations the schema pipeline needs, in :class:`PolicyRow` /
  :class:`GroupingRow` terms. Callers never see the raw enforcer handle or the
  ``list[str]`` row shape.

Why a wrapper rather than methods on the enforcer: the schema applier runs these
operations *inside its own* ``transaction.atomic()`` block and injects a fake in
tests, so the store must (a) own enforcer resolution so callers hold no handle,
(b) never open a transaction of its own, and (c) be trivially substitutable. A
small wrapper satisfies all three while keeping :class:`AuthzEnforcer` focused on
lifecycle. The enforcer is resolved lazily on first use (or injected), so a bare
``PolicyStore()`` is safe to construct before Django settings are configured.
``add_*``/``remove_*`` here mutate the underlying enforcer's in-memory model as
well as the database (via its adapter); the transactional and cache-invalidation
semantics remain the caller's responsibility.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar

from openedx_authz.data import (
    ACTION_NAMESPACE,
    EFFECT_ALLOW,
    POLICY_PTYPE,
    ROLE_NAMESPACE,
    SCOPE_WILDCARD,
    GroupingPolicyIndex,
    PolicyIndex,
)
from openedx_authz.data import AUTHZ_POLICY_ATTRIBUTES_SEPARATOR as SEP
from openedx_authz.engine.enforcer import AuthzEnforcer

__all__ = ["PolicyRow", "GroupingRow", "PolicyStore"]


@dataclass(frozen=True)
class PolicyRow:
    """A single Casbin ``p`` row rendered from a role-permission pair.

    Fields follow the ``p`` shape: subject (role), action (permission), scope
    pattern, effect. Namespacing to the internal Casbin form (``role^``,
    ``act^``, ``<scope>^*``) happens here, at the boundary — schema objects
    never carry those prefixes.

    The Casbin policy type is a fixed ``"p"`` for every rendered definition row.
    """

    PTYPE: ClassVar[str] = POLICY_PTYPE

    subject: str
    action: str
    scope: str
    effect: str

    def as_policy(self) -> list[str]:
        """Return the enforcer arg form: ``[subject, action, scope, effect]``."""
        return [self.subject, self.action, self.scope, self.effect]

    @classmethod
    def from_policy(cls, values: list[str]) -> "PolicyRow":
        """Build from a stored ``p`` row (``[subject, action, scope, effect]``).

        Parsing is delegated to the shared, strict
        :meth:`~openedx_authz.data.PolicyIndex.parse`, so this stays in step
        with the ``api`` layer. A partially populated row is padded first, so an
        in-memory row round-trips instead of being rejected.
        """
        subject, action, scope, effect = PolicyIndex.parse(PolicyIndex.pad(values))
        return cls(subject, action, scope, effect)

    @classmethod
    def from_grant(cls, role_id: str, permission_id: str, scope: str) -> "PolicyRow":
        """Build the Casbin ``p`` row for one ``(role, permission, scope)`` grant.

        The single place the internal namespacing is applied, so every producer
        and consumer of a rendered row agrees on its exact shape. A drift
        between two such places would silently stop a later comparison against
        the stored policy from matching anything.
        """
        return cls(
            subject=f"{ROLE_NAMESPACE}{SEP}{role_id}",
            action=f"{ACTION_NAMESPACE}{SEP}{permission_id}",
            scope=f"{scope}{SEP}{SCOPE_WILDCARD}",
            effect=EFFECT_ALLOW,
        )


@dataclass(frozen=True)
class GroupingRow:
    """A single Casbin ``g`` (grouping) row: one subject-to-role assignment.

    Fields follow the ``g`` shape: ``[subject, role, scope]``. The scope segment
    is optional on a stored row — a scope-less assignment round-trips with an
    empty-string scope rather than being rejected — mirroring Casbin's own
    tolerance (see :meth:`~openedx_authz.data.GroupingPolicyIndex.parse`).

    Modelling the grouping row as a typed value object lets the schema pipeline
    reason about assignments by name (``row.role``, ``row.subject``) instead of
    positional indices into a raw ``list[str]``.
    """

    subject: str
    role: str
    scope: str

    def as_policy(self) -> list[str]:
        """Return the enforcer arg form: ``[subject, role, scope]``."""
        return [self.subject, self.role, self.scope]

    @classmethod
    def from_policy(cls, values: list[str]) -> "GroupingRow":
        """Build from a stored ``g`` row (``[subject, role, scope]``).

        Parsing is delegated to the shared, strict
        :meth:`~openedx_authz.data.GroupingPolicyIndex.parse`, so this stays in
        step with :meth:`PolicyRow.from_policy`. A scope-less row
        (``[subject, role]``) is padded first, so it maps to an empty-string
        scope — the exact tolerance the previous positional access
        (``row[2] if len(row) >= 3 else ""``) encoded inline — instead of being
        rejected.
        """
        subject, role, scope = GroupingPolicyIndex.parse(GroupingPolicyIndex.pad(values))
        return cls(subject, role, scope)


class PolicyStore:
    """Casbin-facing facade exposing only the operations the schema pipeline needs.

    Speaks :class:`PolicyRow` / :class:`GroupingRow` so callers never touch the
    raw ``list[str]`` row shape or the enforcer handle. The underlying enforcer is
    resolved lazily (``AuthzEnforcer.get_enforcer()``) on first use unless one is
    injected, so a caller can build a bare ``PolicyStore()`` and let it manage the
    handle. Deliberately *not* transaction-aware: the mutating methods delegate
    straight to the enforcer, which mutates its in-memory model and database
    together, so the caller remains responsible for wrapping a batch in
    ``transaction.atomic()`` and for invalidating the policy cache on failure.
    """

    def __init__(self, enforcer=None):
        """Args:
        enforcer: An optional Casbin enforcer to operate on — any object exposing
            the ``get_policy``/``add_policy``/``remove_policy``/
            ``get_grouping_policy``/``remove_grouping_policy`` surface (a fake, in
            tests). When omitted, the store resolves ``AuthzEnforcer.get_enforcer()``
            lazily on first use, so callers never have to hold or pass the enforcer
            handle. The store opens no transaction of its own.
        """
        self._enforcer = enforcer

    @property
    def _resolved_enforcer(self):
        """Resolve and cache the enforcer, deferring instantiation to honor timing.

        ``AuthzEnforcer.get_enforcer()`` reads ``CASBIN_MODEL``/``CASBIN_DB_ALIAS``
        and initializes Casbin, so it must run after Django settings are configured
        — never at import or construction time. Resolving on first access (rather
        than in ``__init__``) keeps a bare ``PolicyStore()`` safe to build early
        while still hiding the enforcer handle from callers.
        """
        if self._enforcer is None:
            self._enforcer = AuthzEnforcer.get_enforcer()
        return self._enforcer

    def get_policy_rows(self) -> list[PolicyRow]:
        """Return every stored ``p`` row as a :class:`PolicyRow`."""
        return [PolicyRow.from_policy(row) for row in self._resolved_enforcer.get_policy()]

    def add_policy_row(self, row: PolicyRow) -> bool:
        """Add one ``p`` row. Returns the enforcer's add result (True if added)."""
        return self._resolved_enforcer.add_policy(*row.as_policy())

    def remove_policy_row(self, row: PolicyRow) -> bool:
        """Remove one ``p`` row. Returns the enforcer's remove result (True if removed)."""
        return self._resolved_enforcer.remove_policy(*row.as_policy())

    def get_grouping_rows(self) -> list[GroupingRow]:
        """Return every stored ``g`` (assignment) row as a :class:`GroupingRow`."""
        return [GroupingRow.from_policy(row) for row in self._resolved_enforcer.get_grouping_policy()]

    def remove_grouping_row(self, row: GroupingRow) -> bool:
        """Remove one ``g`` row. Returns the enforcer's remove result (True if removed).

        The row is sent back in its exact stored shape via
        :meth:`GroupingRow.as_policy`, so the exact grouping row is removed rather
        than a reconstructed one.
        """
        return self._resolved_enforcer.remove_grouping_policy(*row.as_policy())

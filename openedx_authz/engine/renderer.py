"""Render compiled definitions to Casbin rows and apply them (ADR 0018 §1, §5).

This is the only Casbin/Django-aware part of the schema pipeline. It implements
the ``render`` and ``apply`` lifecycle steps:

* ``render`` builds the Casbin ``p`` rows for a :class:`CompiledSchema` in
  memory, without touching the database.
* ``apply`` persists the rows in a single transaction, while preserving data
  owned by other services (ADR 0018 §3): dynamic roles, user assignments, and
  the legacy ``g2`` action-inheritance rows that still live in ``authz.policy``.

Key semantics:
    * Idempotent (ADR 0018 §2): re-applying identical definitions changes
      nothing and creates no duplicates.
    * Change report before write (ADR 0018 §6): :meth:`SchemaApplier.plan`
      reports the ``p`` rows that will be added or removed by comparing rendered
      output against the currently stored policy.
    * Removal is force-gated (ADR 0018 §6): removing a role that still has
      assignments requires an explicit force option.

Note on the current transition (see module TODOs): persistent storage of
compiled definitions and their :class:`SourceRecord`s (the definition/source
model of ADR 0018 §3) is not implemented yet, and precise "schema-owned" row
ownership depends on it. Until then, :meth:`SchemaApplier.apply` performs an
additive, idempotent write of rendered ``p`` rows and does not prune stale
rows; :meth:`SchemaApplier.plan` still reports would-be removals for review.

``render`` is pure and imports nothing from Casbin/Django. ``plan``/``apply``
import the enforcer lazily so this module stays importable without a configured
Django environment.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from openedx_authz.data import AUTHZ_POLICY_ATTRIBUTES_SEPARATOR as SEP
from openedx_authz.engine.schema.exceptions import SchemaApplyError
from openedx_authz.engine.schema.types import CompiledSchema, RoleDefinition

logger = logging.getLogger(__name__)

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


@dataclass
class ChangePlan:
    """Diff between rendered definitions and what is currently stored.

    Presented to the operator before any write (ADR 0018 §6).
    """

    added_rows: list[PolicyRow] = field(default_factory=list)
    removed_rows: list[PolicyRow] = field(default_factory=list)
    unchanged: bool = False
    # (role_subject, assignment_subject) pairs: roles being removed that still
    # have user assignments; block removal unless force is set.
    blocking_assignments: list[tuple[str, str]] = field(default_factory=list)


@dataclass
class ApplyResult:
    """Outcome of an apply operation, for reporting."""

    added: int = 0
    removed: int = 0
    unchanged: bool = False


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
            subject = f"{ROLE_PREFIX}{SEP}{role.id}"
            for scope in sorted(role.scopes):
                scope_pattern = f"{scope}{SEP}{SCOPE_WILDCARD}"
                for permission in sorted(role.permissions):
                    rows.append(
                        PolicyRow(
                            ptype=POLICY_PTYPE,
                            subject=subject,
                            action=f"{ACTION_PREFIX}{SEP}{permission}",
                            scope=scope_pattern,
                            effect=ALLOW,
                        )
                    )
        return RenderedPolicy(rows=rows)


class SchemaApplier:
    """Compares, then transactionally applies rendered policy to the database."""

    def __init__(self, enforcer=None):
        """Args:
        enforcer: Casbin enforcer; defaults to ``AuthzEnforcer.get_enforcer()``.

        The default is resolved lazily inside methods (not at import) to respect
        the plugin/settings timing constraint.
        """
        self._enforcer = enforcer

    def plan(self, rendered: RenderedPolicy) -> ChangePlan:
        """Compute the change report without writing (ADR 0018 §6).

        Compares ``rendered`` against the currently stored ``p`` rows. Flags
        roles that would be removed (their subject no longer appears in the
        rendered set) that still have user assignments as blocking.
        """
        enforcer = self._resolve_enforcer()

        rendered_set = set(rendered.rows)
        stored_set = {PolicyRow.from_policy(row) for row in enforcer.get_policy()}

        added = sorted(rendered_set - stored_set, key=self._row_sort_key)
        removed = sorted(stored_set - rendered_set, key=self._row_sort_key)

        rendered_subjects = {row.subject for row in rendered_set}
        removed_subjects = {row.subject for row in removed} - rendered_subjects

        blocking = self._find_blocking_assignments(enforcer, removed_subjects)

        return ChangePlan(
            added_rows=added,
            removed_rows=removed,
            unchanged=not added and not removed,
            blocking_assignments=blocking,
        )

    def apply(
        self,
        rendered: RenderedPolicy,
        schema: CompiledSchema,
        *,
        force: bool = False,
    ) -> ApplyResult:
        """Persist rendered ``p`` rows in one transaction (additive, idempotent).

        Adds rendered rows not already present and invalidates the policy cache
        so the enforcer reloads. Preserves dynamic roles, assignments, and
        ``g2`` rows.

        Pruning of stale rows is deferred pending the definition/source storage
        model (ADR 0018 §3); would-be removals are reported by :meth:`plan` and
        logged here rather than applied. When a removal would drop a role that
        still has assignments, ``force`` must be set to acknowledge it.

        Raises:
            SchemaApplyError: If the plan has blocking assignments and ``force``
                is False.
        """
        from django.db import transaction  # pylint: disable=import-outside-toplevel

        from openedx_authz.engine.enforcer import AuthzEnforcer  # pylint: disable=import-outside-toplevel

        plan = self.plan(rendered)

        if plan.blocking_assignments and not force:
            details = ", ".join(f"{role} (assigned to {subject})" for role, subject in plan.blocking_assignments)
            raise SchemaApplyError(
                "Refusing to proceed: static roles with existing assignments would be removed: "
                f"{details}. Re-run with force to remove them together with their assignments."
            )

        enforcer = self._resolve_enforcer()

        # Persist definition/source rows and add any missing p rows atomically.
        # Definitions are synced even when p rows are unchanged so metadata-only
        # edits land and pre-existing p rows get adopted on first run.
        with transaction.atomic():
            for row in plan.added_rows:
                enforcer.add_policy(*row.as_policy())
            self._store_sources(schema)

        if plan.removed_rows:
            logger.warning(
                "Authz schema apply: %d stale p row(s) detected but NOT removed "
                "(row pruning is deferred pending the definition/source storage model). "
                "Rows: %s",
                len(plan.removed_rows),
                [row.as_policy() for row in plan.removed_rows],
            )

        if plan.added_rows:
            AuthzEnforcer.invalidate_policy_cache()
            logger.info("Authz schema apply: added %d p row(s).", len(plan.added_rows))
        else:
            logger.info("Authz schema apply: policy rows unchanged; definitions synced.")

        return ApplyResult(added=len(plan.added_rows), removed=0, unchanged=plan.unchanged)

    # ---- helpers ----------------------------------------------------------

    def _resolve_enforcer(self):
        """Lazily resolve the enforcer to honor plugin/settings timing."""
        if self._enforcer is None:
            from openedx_authz.engine.enforcer import AuthzEnforcer  # pylint: disable=import-outside-toplevel

            self._enforcer = AuthzEnforcer.get_enforcer()
        return self._enforcer

    @staticmethod
    def _find_blocking_assignments(enforcer, removed_subjects: set[str]) -> list[tuple[str, str]]:
        """Return (role_subject, assignment_subject) for removed roles still assigned.

        Grouping (``g``) rows have the shape ``[subject, role, scope]``; a role
        being removed is blocking if any ``g`` row references it at index 1.
        """
        if not removed_subjects:
            return []
        blocking: list[tuple[str, str]] = []
        for grouping in enforcer.get_grouping_policy():
            if len(grouping) >= 2 and grouping[1] in removed_subjects:
                blocking.append((grouping[1], grouping[0]))
        return sorted(set(blocking))

    @staticmethod
    def _row_sort_key(row: PolicyRow) -> tuple[str, str, str, str]:
        return (row.subject, row.action, row.scope, row.effect)

    def _store_sources(self, schema: CompiledSchema) -> None:
        """Persist compiled definitions and their sources (ADR 0024).

        Upserts categories, permissions, roles, and each ``(role, permission,
        scope)`` grant, linking every definition and grant to its contributing
        sources. Idempotent: re-applying identical schema is a no-op. Pre-existing
        ``p`` rows are adopted because grants are upserted for every rendered
        triple regardless of prior ``p``-row existence.

        Stale-definition pruning is deferred (consistent with ``p``-row pruning);
        this method only upserts.

        Called inside the ``apply`` transaction.
        """
        from openedx_authz.models import schema as m  # pylint: disable=import-outside-toplevel

        source_cache: dict[tuple[str, str], object] = {}

        def source_obj(record):
            key = (record.distribution, record.module)
            cached = source_cache.get(key)
            if cached is not None:
                return cached
            obj, _ = m.AuthzSchemaSource.objects.update_or_create(
                distribution=record.distribution,
                module=record.module,
                defaults={
                    "distribution_version": record.distribution_version,
                    "resource_path": record.resource_path,
                    "content_digest": record.content_digest,
                    "schema_version": record.schema_version,
                },
            )
            source_cache[key] = obj
            return obj

        # Categories.
        category_objs: dict[str, object] = {}
        for cid, compiled in schema.categories.items():
            definition = compiled.definition
            obj, _ = m.AuthzPermissionCategory.objects.update_or_create(
                category_id=definition.id,
                defaults={
                    "display_name": definition.display_name,
                    "description": definition.description or "",
                    "icon": definition.icon,
                },
            )
            category_objs[cid] = obj
            for record in compiled.sources:
                m.AuthzCategorySource.objects.update_or_create(
                    category=obj, source=source_obj(record), defaults={"origin_kind": m.OriginKind.BASE}
                )

        # Permissions.
        permission_objs: dict[str, object] = {}
        for pid, compiled in schema.permissions.items():
            definition = compiled.definition
            obj, _ = m.AuthzPermissionDefinition.objects.update_or_create(
                namespace=definition.namespace,
                name=definition.name,
                defaults={
                    "display_name": definition.display_name,
                    "description": definition.description or "",
                    "category": category_objs.get(definition.category),
                    "scopes": list(definition.scopes),
                    "icon": definition.icon,
                },
            )
            permission_objs[pid] = obj
            for record in compiled.sources:
                m.AuthzPermissionSource.objects.update_or_create(
                    permission=obj, source=source_obj(record), defaults={"origin_kind": m.OriginKind.BASE}
                )

        # Roles.
        role_objs: dict[str, object] = {}
        for rid, compiled in schema.roles.items():
            definition = compiled.definition
            obj, _ = m.AuthzRoleDefinition.objects.update_or_create(
                role_id=definition.id,
                defaults={
                    "display_name": definition.display_name,
                    "description": definition.description or "",
                    "scopes": list(definition.scopes),
                    "icon": definition.icon,
                    "hidden": definition.hidden,
                },
            )
            role_objs[rid] = obj
            for record in compiled.sources:
                m.AuthzRoleSource.objects.update_or_create(
                    role=obj, source=source_obj(record), defaults={"origin_kind": m.OriginKind.BASE}
                )

        # Role-permission grants (one per rendered role/permission/scope triple).
        for rid, compiled in schema.roles.items():
            role_obj = role_objs[rid]
            definition = compiled.definition
            for scope in definition.scopes:
                for perm_id in definition.permissions:
                    permission_obj = permission_objs.get(perm_id)
                    if permission_obj is None:
                        continue  # validated away in practice; skip defensively
                    grant, _ = m.AuthzRolePermission.objects.update_or_create(
                        role=role_obj, permission=permission_obj, scope=scope
                    )
                    for rel in schema.role_permission_sources.get((rid, perm_id), []):
                        m.AuthzRolePermissionSource.objects.update_or_create(
                            role_permission=grant,
                            source=source_obj(rel.source),
                            defaults={"origin_kind": rel.origin_kind, "priority": rel.priority},
                        )

        logger.info(
            "Authz schema apply: persisted %d role(s), %d permission(s), %d category(ies).",
            len(schema.roles),
            len(schema.permissions),
            len(schema.categories),
        )

"""Resolve documents into one set of static definitions (the ``compile`` step).

Compilation (ADR 0018 §1) merges base definitions across all documents and
applies ``role_extensions`` per ADR 0023:

    * Extensions resolve only after every role and permission is loaded.
    * An extension changes only the fields it includes; absent fields keep
      their current value; it cannot change a role ID.
    * Different fields from different contributions combine.
    * ``priority`` resolves conflicts on the same metadata field or the same
      permission (higher wins). Equal priority with disagreeing values raises
      :class:`SchemaCompileError` so deployment stops before the database
      changes.
    * Adding a permission the role already has, or removing one it lacks, is a
      no-op logged as a warning.

Every resulting :class:`CompiledDefinition` retains all contributing
:class:`SourceRecord` values, and each role-permission grant is attributed at
the (role, permission) grain with its origin (base vs extension) for ADR 0025
source tracking. Output is deterministic regardless of discovery order. No
Casbin/Django imports.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, replace

from openedx_authz.constants import SchemaOriginKind
from openedx_authz.engine.schema.exceptions import SchemaCompileError
from openedx_authz.engine.schema.types import (
    CompiledDefinition,
    CompiledSchema,
    RelationshipSource,
    RoleDefinition,
    SchemaDocument,
    SourceRecord,
)

logger = logging.getLogger(__name__)

# Metadata fields an extension may replace on a role.
_METADATA_FIELDS = ("display_name", "description", "icon", "hidden")

# Singular labels for operator-facing messages, keyed by document attribute.
_KIND_LABELS = {"categories": "category", "permissions": "permission", "roles": "role"}


@dataclass(frozen=True)
class _Tracked:
    """A base definition plus the sources and priority that produced it.

    Immutable: resolution steps return a new ``_Tracked`` via
    :func:`dataclasses.replace` rather than mutating one in place.
    """

    definition: object
    sources: tuple[SourceRecord, ...] = ()
    priority: int = 0


class SchemaCompiler:
    """Merges validated documents into a :class:`CompiledSchema`."""

    def compile(self, documents: list[SchemaDocument]) -> CompiledSchema:
        """Resolve categories, permissions, roles, and extensions.

        Assumes ``documents`` already passed validation.

        Raises:
            SchemaCompileError: On an unresolvable equal-priority conflict.
        """
        categories = self._collect(documents, "categories", key=lambda c: c.id)
        permissions = self._collect(documents, "permissions", key=lambda p: p.identifier)
        roles = self._collect(documents, "roles", key=lambda r: r.id)

        resolved_roles, role_permission_sources = self._resolve_roles_and_provenance(roles, documents)

        return CompiledSchema(
            categories=self._finalize(categories),
            permissions=self._finalize(permissions),
            roles=self._finalize(resolved_roles),
            role_permission_sources=role_permission_sources,
        )

    def _collect(self, documents: list[SchemaDocument], attr: str, key) -> dict[str, _Tracked]:
        """Gather base definitions keyed by identifier, resolving by priority.

        Higher priority wins on conflict; equal priority with differing content
        raises; identical duplicates merge their sources.
        """
        tracked: dict[str, _Tracked] = {}
        for document in documents:
            for definition in getattr(document, attr):
                identifier = key(definition)
                existing = tracked.get(identifier)
                if existing is None:
                    tracked[identifier] = _Tracked(
                        definition=definition,
                        sources=(document.source,),
                        priority=document.priority,
                    )
                    continue

                kind = _KIND_LABELS.get(attr, attr)
                tracked[identifier] = self._resolve_priority(
                    kind,
                    identifier,
                    existing=existing,
                    incoming=_Tracked(
                        definition=definition,
                        sources=(document.source,),
                        priority=document.priority,
                    ),
                )
        return tracked

    def _resolve_priority(
        self,
        kind: str,
        identifier: str,
        *,
        existing: _Tracked,
        incoming: _Tracked,
    ) -> _Tracked:
        """Resolve two competing definitions for one identifier by priority.

        Single responsibility: decide which of two :class:`_Tracked` entries for
        the same identifier survives.

        * Identical definitions merge their sources (both files contributed the
          same thing).
        * Otherwise higher priority wins; the loser is warned about (ADR 0017
          §4) so a valid-but-ineffective file does not look like it took effect.
        * Equal priority with disagreeing definitions is unresolvable and raises
          :class:`SchemaCompileError` so deployment stops before the database
          changes.

        Each ``_Tracked`` carries a single source; ``existing`` and ``incoming``
        are symmetric, so this also serves conflicts between extension
        contributions where only priority (not load order) decides the winner.
        """
        if existing.definition == incoming.definition:
            return replace(existing, sources=existing.sources + incoming.sources)
        if incoming.priority == existing.priority:
            raise SchemaCompileError(
                f"Conflicting {kind} definition for {identifier!r} at equal priority "
                f"{incoming.priority} "
                f"({existing.sources[0].source_id} vs {incoming.sources[0].source_id})."
            )
        winner, loser = (
            (incoming, existing) if incoming.priority > existing.priority else (existing, incoming)
        )
        self._warn_discarded(
            kind,
            identifier,
            loser=loser.sources[0],
            loser_priority=loser.priority,
            winner=winner.sources[0],
            winner_priority=winner.priority,
        )
        return winner

    @staticmethod
    def _warn_discarded(
        kind: str,
        identifier: str,
        *,
        loser: SourceRecord,
        loser_priority: int,
        winner: SourceRecord,
        winner_priority: int,
    ) -> None:
        """Report a contribution that lost to a higher-priority one.

        Priority silently picking a winner is the behavior operators find hardest
        to debug: the losing file is valid, was loaded, and simply has no effect.
        ADR 0017 §4 requires warning about exactly this.
        """
        logger.warning(
            "authz schema: %s %r from %s (priority %s) has no effect; %s (priority %s) takes precedence.",
            kind,
            identifier,
            loser.source_id,
            loser_priority,
            winner.source_id,
            winner_priority,
        )

    def _resolve_roles_and_provenance(
        self, roles: dict[str, _Tracked], documents: list[SchemaDocument]
    ) -> tuple[dict[str, _Tracked], dict[tuple[str, str], list[RelationshipSource]]]:
        """Apply extensions and build per-(role, permission) provenance.

        Seeds base provenance from each role's own definition, then folds in
        ``role_extensions`` (metadata replacement + permission add/remove),
        honoring priority. Returns the resolved roles (a new mapping; inputs are
        left untouched) alongside the relationship provenance map.
        """
        metadata_changes, permission_changes = self._gather_extension_changes(roles, documents)
        resolved_roles: dict[str, _Tracked] = {}
        role_permission_sources: dict[tuple[str, str], list[RelationshipSource]] = {}

        for role_id, tracked in roles.items():
            base_sources = tracked.sources
            base_priority = tracked.priority

            tracked = self._apply_metadata_changes(role_id, tracked, metadata_changes.get(role_id, {}))

            tracked, provenance = self._apply_permission_changes(
                role_id,
                tracked,
                base_sources,
                base_priority,
                permission_changes.get(role_id),
            )

            resolved_roles[role_id] = tracked
            for perm, sources in provenance.items():
                role_permission_sources[(role_id, perm)] = sources

        return resolved_roles, role_permission_sources

    def _apply_metadata_changes(
        self,
        role_id: str,
        tracked: _Tracked,
        metadata_changes_for_role: dict[str, list[tuple[object, int, SourceRecord]]],
    ) -> _Tracked:
        """Return the role with winning metadata applied and its sources recorded.

        Single responsibility: resolve the winning metadata values for this role
        and produce a new :class:`_Tracked` carrying the updated definition and
        the sources that contributed them. Returns ``tracked`` unchanged when the
        role has no metadata extensions.
        """
        if not metadata_changes_for_role:
            return tracked
        new_values, contributing_sources = self._resolve_metadata(role_id, metadata_changes_for_role)
        merged_sources = tracked.sources + tuple(
            src for src in contributing_sources if src not in tracked.sources
        )
        return replace(
            tracked,
            definition=replace(tracked.definition, **new_values),
            sources=merged_sources,
        )

    def _apply_permission_changes(
        self,
        role_id: str,
        tracked: _Tracked,
        base_sources: tuple[SourceRecord, ...],
        base_priority: int,
        permission_changes_for_role: dict[str, list[tuple[str, int, SourceRecord]]] | None,
    ) -> tuple[_Tracked, dict[str, list[RelationshipSource]]]:
        """Return the role with permission changes applied and its provenance.

        Single responsibility: own the per-permission provenance for this role.
        Seeds base provenance from the role's declared permissions, then, if the
        role has permission extensions, resolves the final permission set,
        produces a new :class:`_Tracked`, and reflects the add/remove in
        provenance. Returns ``(tracked, base_provenance)`` unchanged when the
        role has no permission extensions.
        """
        base_provenance: dict[str, list[RelationshipSource]] = {
            perm: [RelationshipSource(src, SchemaOriginKind.BASE, base_priority) for src in base_sources]
            for perm in tracked.definition.permissions
        }
        if not permission_changes_for_role or not (
            permission_changes_for_role["add"] or permission_changes_for_role["remove"]
        ):
            return tracked, base_provenance
        final_perms, provenance = self._resolve_permissions(
            role_id,
            tracked.definition.permissions,
            base_sources,
            base_priority,
            permission_changes_for_role,
        )
        tracked = replace(tracked, definition=replace(tracked.definition, permissions=final_perms))
        return tracked, provenance

    def _gather_extension_changes(self, roles: dict[str, _Tracked], documents: list[SchemaDocument]):
        """Collect per-role metadata and permission changes from all extensions.

        Entries carry the full :class:`SourceRecord` and priority so provenance
        and conflict resolution have everything they need.
        """
        metadata_changes: dict[str, dict[str, list[tuple[object, int, SourceRecord]]]] = {}
        permission_changes: dict[str, dict[str, list[tuple[str, int, SourceRecord]]]] = {}

        for document in documents:
            for extension in document.role_extensions:
                role_id = extension.role_id
                if role_id not in roles:
                    # Validation already errors on this; skip defensively.
                    continue
                metadata_changes_for_role = metadata_changes.setdefault(role_id, {})
                for field_name in _METADATA_FIELDS:
                    value = getattr(extension, field_name)
                    if value is not None:
                        metadata_changes_for_role.setdefault(field_name, []).append(
                            (value, document.priority, document.source)
                        )
                permission_changes_for_role = permission_changes.setdefault(role_id, {"add": [], "remove": []})
                for perm in extension.add_permissions:
                    permission_changes_for_role["add"].append((perm, document.priority, document.source))
                for perm in extension.remove_permissions:
                    permission_changes_for_role["remove"].append((perm, document.priority, document.source))
        return metadata_changes, permission_changes

    def _resolve_contributions(
        self,
        identifier: str,
        entries: list[tuple[object, int, SourceRecord]],
        *,
        loser_kind,
        on_tie,
    ) -> tuple[object, int, list[SourceRecord]]:
        """Pick the winning value among competing extension contributions.

        The batch counterpart to :meth:`_resolve_priority`: where that method
        decides between two base definitions pairwise, this decides among any
        number of ``(value, priority, source)`` contributions to the same
        extension field or permission.

        The highest priority wins. Every contribution in the top-priority group
        must agree; if they do not, ``on_tie(top_values)`` builds the message
        for a :class:`SchemaCompileError` (the caller knows how to describe its
        own conflict). Lower-priority contributions are warned about so a
        valid-but-ineffective file is not mistaken for one that took effect
        (ADR 0017 §4); ``loser_kind(value)`` labels each loser so the warning
        can name what that contribution tried to do.

        Returns the winning value, the winning priority, and every source in the
        winning group (for provenance).
        """
        max_priority = max(priority for _, priority, _ in entries)
        top_values = {value for value, priority, _ in entries if priority == max_priority}
        if len(top_values) > 1:
            raise SchemaCompileError(on_tie(top_values))

        winner_value = next(iter(top_values))
        winning_sources = [src for value, priority, src in entries if priority == max_priority]
        for value, priority, src in entries:
            if priority < max_priority:
                self._warn_discarded(
                    loser_kind(value),
                    identifier,
                    loser=src,
                    loser_priority=priority,
                    winner=winning_sources[0],
                    winner_priority=max_priority,
                )
        return winner_value, max_priority, winning_sources

    def _resolve_metadata(
        self, role_id: str, metadata_changes: dict[str, list[tuple[object, int, SourceRecord]]]
    ):
        """Pick winning metadata values by priority; error on equal-priority ties."""
        new_values: dict[str, object] = {}
        contributing: set[SourceRecord] = set()
        for field_name, entries in metadata_changes.items():
            value, _, winning_sources = self._resolve_contributions(
                role_id,
                entries,
                loser_kind=lambda _value: f"role_extension {field_name}",
                on_tie=lambda top: (
                    f"Conflicting {field_name!r} for role {role_id!r} at equal priority "
                    f"{max(p for _, p, _ in entries)}: {sorted(map(str, top))}."
                ),
            )
            new_values[field_name] = value
            contributing.update(winning_sources)
        return new_values, contributing

    def _resolve_permissions(
        self,
        role_id: str,
        base: tuple[str, ...],
        base_sources: list[SourceRecord],
        base_priority: int,
        permission_changes: dict[str, list[tuple[str, int, SourceRecord]]],
    ):
        """Apply add/remove per permission, returning (final_perms, provenance).

        Add-vs-remove conflicts resolve by priority; equal priority raises.
        Provenance keeps base attribution and appends extension attribution for
        added permissions.
        """
        current = set(base)
        provenance: dict[str, list[RelationshipSource]] = {
            perm: [RelationshipSource(src, SchemaOriginKind.BASE, base_priority) for src in base_sources]
            for perm in base
        }

        actions: dict[str, list[tuple[str, int, SourceRecord]]] = {}
        for perm, priority, src in permission_changes["add"]:
            actions.setdefault(perm, []).append(("add", priority, src))
        for perm, priority, src in permission_changes["remove"]:
            actions.setdefault(perm, []).append(("remove", priority, src))

        for perm, entries in actions.items():
            action, max_priority, winning_sources = self._resolve_contributions(
                role_id,
                entries,
                loser_kind=lambda act, _perm=perm: f"role_extension {act} of {_perm!r} on role",
                on_tie=lambda _top: (
                    f"Conflicting add/remove for permission {perm!r} on role {role_id!r} "
                    f"at equal priority {max(p for _, p, _ in entries)}."
                ),
            )

            if action == "add":
                if perm in current:
                    logger.warning("role_extension adds %r already on role %r; no-op.", perm, role_id)
                current.add(perm)
                provenance.setdefault(perm, [])
                provenance[perm].extend(
                    RelationshipSource(src, SchemaOriginKind.EXTENSION, max_priority) for src in winning_sources
                )
            else:  # remove
                if perm not in current:
                    logger.warning("role_extension removes %r not on role %r; no-op.", perm, role_id)
                current.discard(perm)
                provenance.pop(perm, None)

        return tuple(sorted(current)), provenance

    def _finalize(self, tracked: dict[str, _Tracked]) -> dict[str, CompiledDefinition]:
        """Turn tracked definitions into CompiledDefinition entries."""
        return {
            identifier: CompiledDefinition(
                key=identifier,
                definition=entry.definition,
                sources=entry.sources,
            )
            for identifier, entry in tracked.items()
        }

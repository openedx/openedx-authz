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
the (role, permission) grain with its origin (base vs extension) for ADR 0024
source tracking. Output is deterministic regardless of discovery order. No
Casbin/Django imports.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field, replace

from openedx_authz.engine.schema.exceptions import SchemaCompileError
from openedx_authz.engine.schema.types import (
    ORIGIN_BASE,
    ORIGIN_EXTENSION,
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


@dataclass
class _Tracked:
    """A base definition plus the sources and priority that produced it."""

    definition: object
    sources: list[SourceRecord] = field(default_factory=list)
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

        role_permission_sources = self._resolve_roles_and_provenance(roles, documents)

        return CompiledSchema(
            categories=self._finalize(categories, "category"),
            permissions=self._finalize(permissions, "permission"),
            roles=self._finalize(roles, "role"),
            role_permission_sources=role_permission_sources,
        )

    # ---- base collection --------------------------------------------------

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
                        sources=[document.source],
                        priority=document.priority,
                    )
                    continue

                if existing.definition == definition:
                    existing.sources.append(document.source)
                elif document.priority > existing.priority:
                    tracked[identifier] = _Tracked(
                        definition=definition,
                        sources=[document.source],
                        priority=document.priority,
                    )
                elif document.priority == existing.priority:
                    raise SchemaCompileError(
                        f"Conflicting {attr[:-1]} definition for {identifier!r} at equal priority "
                        f"{document.priority} ({existing.sources[0].source_id} vs {document.source.source_id})."
                    )
                # else: lower priority, keep existing.
        return tracked

    # ---- roles + provenance ----------------------------------------------

    def _resolve_roles_and_provenance(
        self, roles: dict[str, _Tracked], documents: list[SchemaDocument]
    ) -> dict[tuple[str, str], list[RelationshipSource]]:
        """Apply extensions and build per-(role, permission) provenance.

        Seeds base provenance from each role's own definition, then folds in
        ``role_extensions`` (metadata replacement + permission add/remove),
        honoring priority. Returns the relationship provenance map.
        """
        metadata_changes, perm_changes = self._gather_extension_changes(roles, documents)
        rp_sources: dict[tuple[str, str], list[RelationshipSource]] = {}

        for role_id, tracked in roles.items():
            role: RoleDefinition = tracked.definition
            base_sources = list(tracked.sources)
            base_priority = tracked.priority

            # Seed base provenance for every permission the role declares.
            provenance: dict[str, list[RelationshipSource]] = {
                perm: [RelationshipSource(src, ORIGIN_BASE, base_priority) for src in base_sources]
                for perm in role.permissions
            }

            md = metadata_changes.get(role_id, {})
            if md:
                new_values, contributing_sources = self._resolve_metadata(role_id, md)
                tracked.definition = replace(role, **new_values)
                role = tracked.definition
                for src in contributing_sources:
                    if src not in tracked.sources:
                        tracked.sources.append(src)

            pc = perm_changes.get(role_id)
            if pc and (pc["add"] or pc["remove"]):
                final_perms, provenance = self._resolve_permissions(
                    role_id, role.permissions, base_sources, base_priority, pc
                )
                tracked.definition = replace(tracked.definition, permissions=final_perms)

            for perm, sources in provenance.items():
                rp_sources[(role_id, perm)] = sources

        return rp_sources

    def _gather_extension_changes(self, roles: dict[str, _Tracked], documents: list[SchemaDocument]):
        """Collect per-role metadata and permission changes from all extensions.

        Entries carry the full :class:`SourceRecord` and priority so provenance
        and conflict resolution have everything they need.
        """
        metadata_changes: dict[str, dict[str, list[tuple[object, int, SourceRecord]]]] = {}
        perm_changes: dict[str, dict[str, list[tuple[str, int, SourceRecord]]]] = {}

        for document in documents:
            for extension in document.role_extensions:
                role_id = extension.role
                if role_id not in roles:
                    # Validation already errors on this; skip defensively.
                    continue
                md = metadata_changes.setdefault(role_id, {})
                for field_name in _METADATA_FIELDS:
                    value = getattr(extension, field_name)
                    if value is not None:
                        md.setdefault(field_name, []).append((value, document.priority, document.source))
                pc = perm_changes.setdefault(role_id, {"add": [], "remove": []})
                for perm in extension.add_permissions:
                    pc["add"].append((perm, document.priority, document.source))
                for perm in extension.remove_permissions:
                    pc["remove"].append((perm, document.priority, document.source))
        return metadata_changes, perm_changes

    def _resolve_metadata(self, role_id: str, md: dict[str, list[tuple[object, int, SourceRecord]]]):
        """Pick winning metadata values by priority; error on equal-priority ties."""
        new_values: dict[str, object] = {}
        contributing: set[SourceRecord] = set()
        for field_name, entries in md.items():
            max_priority = max(priority for _, priority, _ in entries)
            top_values = {value for value, priority, _ in entries if priority == max_priority}
            if len(top_values) > 1:
                raise SchemaCompileError(
                    f"Conflicting {field_name!r} for role {role_id!r} at equal priority "
                    f"{max_priority}: {sorted(map(str, top_values))}."
                )
            new_values[field_name] = next(iter(top_values))
            contributing.update(src for _, priority, src in entries if priority == max_priority)
        return new_values, contributing

    def _resolve_permissions(
        self,
        role_id: str,
        base: tuple[str, ...],
        base_sources: list[SourceRecord],
        base_priority: int,
        pc: dict[str, list[tuple[str, int, SourceRecord]]],
    ):
        """Apply add/remove per permission, returning (final_perms, provenance).

        Add-vs-remove conflicts resolve by priority; equal priority raises.
        Provenance keeps base attribution and appends extension attribution for
        added permissions.
        """
        current = set(base)
        provenance: dict[str, list[RelationshipSource]] = {
            perm: [RelationshipSource(src, ORIGIN_BASE, base_priority) for src in base_sources] for perm in base
        }

        actions: dict[str, list[tuple[str, int, SourceRecord]]] = {}
        for perm, priority, src in pc["add"]:
            actions.setdefault(perm, []).append(("add", priority, src))
        for perm, priority, src in pc["remove"]:
            actions.setdefault(perm, []).append(("remove", priority, src))

        for perm, entries in actions.items():
            max_priority = max(priority for _, priority, _ in entries)
            top = {action for action, priority, _ in entries if priority == max_priority}
            if len(top) > 1:
                raise SchemaCompileError(
                    f"Conflicting add/remove for permission {perm!r} on role {role_id!r} "
                    f"at equal priority {max_priority}."
                )
            action = next(iter(top))
            winning_sources = [src for act, priority, src in entries if priority == max_priority and act == action]

            if action == "add":
                if perm in current:
                    logger.warning("role_extension adds %r already on role %r; no-op.", perm, role_id)
                current.add(perm)
                provenance.setdefault(perm, [])
                provenance[perm].extend(
                    RelationshipSource(src, ORIGIN_EXTENSION, max_priority) for src in winning_sources
                )
            else:  # remove
                if perm not in current:
                    logger.warning("role_extension removes %r not on role %r; no-op.", perm, role_id)
                current.discard(perm)
                provenance.pop(perm, None)

        return tuple(sorted(current)), provenance

    # ---- finalize ---------------------------------------------------------

    def _finalize(self, tracked: dict[str, _Tracked], kind: str) -> dict[str, CompiledDefinition]:
        """Turn tracked definitions into CompiledDefinition entries."""
        return {
            identifier: CompiledDefinition(
                kind=kind,
                key=identifier,
                definition=entry.definition,
                sources=tuple(entry.sources),
            )
            for identifier, entry in tracked.items()
        }

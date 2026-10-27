"""Convert parsed mappings into schema documents (the ``load`` step, ADR 0018).

Each parsed document already contains its YAML mapping and source record. This
step performs only typed structural shaping. Semantic checks belong to
:mod:`.validation` and cross-file resolution belongs to :mod:`.compilation`.

No Casbin or Django imports, so it stays unit-testable in isolation.
"""

from __future__ import annotations

from openedx_authz.engine.schema.exceptions import SchemaLoadError
from openedx_authz.engine.schema.types import (
    ParsedSchemaDocument,
    PermissionCategory,
    PermissionDefinition,
    RoleDefinition,
    RoleExtension,
    SchemaDocument,
    SourceRecord,
)


class SchemaLoader:
    """Turn structurally valid parsed documents into typed schema documents.

    Resource reading, YAML parsing, content digests, and distribution metadata
    belong to :class:`~openedx_authz.engine.schema.parsing.SchemaParser`. This
    class owns only the conversion into typed definitions.
    """

    def load(self, documents: list[ParsedSchemaDocument]) -> list[SchemaDocument]:
        """Load every parsed mapping into a :class:`SchemaDocument`.

        Raises:
            SchemaLoadError: If called with a root value that is not a mapping.
        """
        loaded = []
        for document in documents:
            if not isinstance(document.data, dict):
                raise SchemaLoadError(f"{document.source.source_id}: schema document must be a mapping.")
            loaded.append(self._build_document(document.data, document.source))
        return loaded

    def _build_document(self, raw: dict, source: SourceRecord) -> SchemaDocument:
        """Map the parsed mapping's blocks into a typed SchemaDocument.

        ``priority`` is a *required* field per ``authz-schema-v1.json``; a higher
        value wins when contributions conflict (see
        ``docs/references/authorization-schema.rst``). JSON Schema validates
        its presence and type before this method runs. The fallback to ``0``
        and conversion error remain defensive behavior for direct loader use.
        """
        try:
            priority = int(raw.get("priority", 0))
        except (TypeError, ValueError) as exc:
            raise SchemaLoadError(
                f"{source.source_id}: 'priority' must be an integer, got {raw.get('priority')!r}."
            ) from exc

        return SchemaDocument(
            source=source,
            priority=priority,
            categories=[self._build_category(item, source) for item in raw.get("permission_categories", []) or []],
            permissions=[self._build_permission(item, source) for item in raw.get("permissions", []) or []],
            roles=[self._build_role(item, source) for item in raw.get("roles", []) or []],
            role_extensions=[self._build_extension(item, source) for item in raw.get("role_extensions", []) or []],
        )

    @staticmethod
    def _as_tuple(value) -> tuple[str, ...]:
        """Coerce a YAML list (or None) into a tuple of strings."""
        if not value:
            return ()
        if isinstance(value, str):
            return (value,)
        return tuple(str(item) for item in value)

    def _build_category(self, item: dict, source: SourceRecord) -> PermissionCategory:
        """Build a ``PermissionCategory`` from one ``permission_categories`` entry."""
        self._require_mapping(item, "permission_categories", source)
        return PermissionCategory(
            id=item.get("id", ""),
            display_name=item.get("display_name", ""),
            description=item.get("description", ""),
            icon=item.get("icon"),
        )

    def _build_permission(self, item: dict, source: SourceRecord) -> PermissionDefinition:
        """Build a ``PermissionDefinition`` from one ``permissions`` entry."""
        self._require_mapping(item, "permissions", source)
        return PermissionDefinition(
            namespace=item.get("namespace", ""),
            name=item.get("name", ""),
            display_name=item.get("display_name", ""),
            description=item.get("description", ""),
            category_id=item.get("category_id", ""),
            scopes=self._as_tuple(item.get("scopes")),
            icon=item.get("icon"),
        )

    def _build_role(self, item: dict, source: SourceRecord) -> RoleDefinition:
        """Build a ``RoleDefinition`` from one ``roles`` entry."""
        self._require_mapping(item, "roles", source)
        return RoleDefinition(
            id=item.get("id", ""),
            display_name=item.get("display_name", ""),
            description=item.get("description", ""),
            scopes=self._as_tuple(item.get("scopes")),
            permissions=self._as_tuple(item.get("permissions")),
            icon=item.get("icon"),
            hidden=bool(item.get("hidden", False)),
        )

    def _build_extension(self, item: dict, source: SourceRecord) -> RoleExtension:
        """Build a ``RoleExtension`` from one ``role_extensions`` entry.

        ``hidden`` is read as tri-state: absent stays ``None`` ("leave
        unchanged"), distinct from an explicit ``False`` (ADR 0023 §1).
        """
        self._require_mapping(item, "role_extensions", source)
        return RoleExtension(
            role_id=item.get("role_id", ""),
            add_permissions=self._as_tuple(item.get("add_permissions")),
            remove_permissions=self._as_tuple(item.get("remove_permissions")),
            display_name=item.get("display_name"),
            description=item.get("description"),
            icon=item.get("icon"),
            hidden=item.get("hidden"),  # tri-state: None means "leave unchanged"
        )

    @staticmethod
    def _require_mapping(item, block: str, source: SourceRecord) -> None:
        """Raise ``SchemaLoadError`` (naming the block and source) if ``item`` is not a mapping."""
        if not isinstance(item, dict):
            raise SchemaLoadError(
                f"{source.source_id}: each entry in '{block}' must be a mapping, got {type(item).__name__}."
            )

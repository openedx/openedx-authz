"""Validate schema documents individually and as a whole (the ``validate`` step).

Rules come from ADR 0017 §4 and the field reference:

Per-document checks:
    * Static role IDs do not start with the prefix reserved for custom roles (ADR 0035).
    * Roles with no base permissions are accepted with a warning because
      ``role_extensions`` may contribute their complete permission set.
    * ``icon`` values, where present, are valid ``@openedx/paragon/icons`` names
      (ADR 0017 §4). The allowed set is vendored in :mod:`paragon_icons`
      (regenerate with ``make paragon_icons``; see ADR 0029).

Whole-set checks (after all documents load):
    * Every permission ``category`` references an existing category.
    * Every role/extension permission references an existing permission.
    * A role's ``scopes`` are supported by each of its permissions.
    * ``role_extensions`` target an existing role (ADR 0023).
    * Conflicting duplicate base definitions fail; identical duplicates warn.
    * Every ``depends_on`` entry references an existing permission whose scopes
      include every scope of the dependent permission, and dependencies form
      no cycle, including a permission that depends on itself (ADR 0034 §3).

Post-compile checks (after extensions and priority are resolved):
    * A role's ``scopes`` are supported by every permission it *ends up* with,
      including permissions contributed by ``role_extensions``.
    * The resolved permissions and categories still exist.
    * A role that ends up with a permission also ends up with all of its direct
      and indirect dependencies, whatever ``schema_version`` its files declare
      (ADR 0034 §3).
    * A visible permission does not depend on a hidden permission or on a
      permission in a hidden category.

Validation collects issues rather than raising on the first problem, so the
deployment report can list every error and warning at once. No Casbin imports.
"""

from __future__ import annotations

from collections.abc import Container

from openedx_authz.constants import CUSTOM_ROLE_ID_PREFIX, SchemaOriginKind
from openedx_authz.engine.schema.dependencies import find_cycles, missing_dependencies
from openedx_authz.engine.schema.issues import IssueLevel, ValidationIssue
from openedx_authz.engine.schema.paragon_icons import PARAGON_ICON_NAMES
from openedx_authz.engine.schema.types import (
    CompiledSchema,
    PermissionDefinition,
    SchemaDocument,
)


class SchemaValidator:
    """Runs per-document and whole-set validation."""

    def validate(self, documents: list[SchemaDocument]) -> list[ValidationIssue]:
        """Run per-document then whole-set validation, returning all issues."""
        issues = []
        for document in documents:
            issues.extend(self.validate_document(document))
        issues.extend(self.validate_set(documents))
        return issues

    def validate_compiled(self, schema: CompiledSchema) -> list[ValidationIssue]:
        """Re-check the resolved schema after extensions and priority are applied.

        Document-level validation only sees base declarations, so a
        ``role_extension`` that adds a permission is checked for existence but
        never for scope compatibility. Without this pass an extension can grant
        a permission in a scope the permission does not support, and the
        renderer still emits an enforceable ``p`` row for it (ADR 0017 §4,
        ADR 0023 §3).

        The compiled role's permission set is the one that becomes Casbin ``p``
        rows, so it is the set that has to satisfy the scope rule.
        """
        issues: list[ValidationIssue] = []

        for role_id, compiled_role in schema.roles.items():
            role = compiled_role.definition
            for perm_id in role.permissions:
                compiled_permission = schema.permissions.get(perm_id)
                permission_scopes = compiled_permission.definition.scopes if compiled_permission else None
                issues.extend(
                    self._check_role_permission_scope(
                        role_id,
                        perm_id,
                        role.scopes,
                        permission_scopes,
                        self._role_permission_source_id(schema, role_id, perm_id),
                        missing_verb="resolves to",
                    )
                )

        for perm_id, compiled_permission in schema.permissions.items():
            sources = compiled_permission.sources
            issues.extend(
                self._check_permission_category(
                    perm_id,
                    compiled_permission.definition.category_id,
                    schema.categories,
                    sources[0].source_id if sources else None,
                )
            )

        issues.extend(self._check_role_dependencies(schema))
        issues.extend(self._check_visible_dependencies(schema))

        return issues

    def validate_document(self, document: SchemaDocument) -> list[ValidationIssue]:
        """Per-file checks that need no cross-file context."""
        issues: list[ValidationIssue] = []
        sid = document.source.source_id

        for category in document.categories:
            issues.extend(self._check_icon(category.icon, f"category {category.id}", sid))

        for permission in document.permissions:
            issues.extend(self._check_icon(permission.icon, f"permission {permission.identifier}", sid))

        for role in document.roles:
            issues.extend(self._check_icon(role.icon, f"role {role.id}", sid))
            issues.extend(self._check_role_id_prefix(role.id, sid))
            issues.extend(self._check_permissions(role.id, role.permissions, sid))

        for extension in document.role_extensions:
            issues.extend(self._check_icon(extension.icon, f"role_extension {extension.role_id}", sid))

        return issues

    def validate_set(self, documents: list[SchemaDocument]) -> list[ValidationIssue]:
        """Whole-set checks across all loaded documents."""
        issues: list[ValidationIssue] = []

        category_ids: set[str] = set()
        permission_index: dict[str, tuple[str, ...]] = {}  # id -> scopes
        role_ids: set[str] = set()

        issues.extend(self._collect_and_check_duplicates(documents, category_ids, permission_index, role_ids))
        issues.extend(self._check_permission_dependencies(documents))

        # Reference integrity: permission categories exist.
        for document in documents:
            sid = document.source.source_id
            for permission in document.permissions:
                issues.extend(
                    self._check_permission_category(permission.identifier, permission.category_id, category_ids, sid)
                )

            # Role permissions exist, and role scopes are supported by each permission.
            for role in document.roles:
                for perm_id in role.permissions:
                    issues.extend(
                        self._check_role_permission_scope(
                            role.id,
                            perm_id,
                            role.scopes,
                            permission_index.get(perm_id),
                            sid,
                            missing_verb="references",
                        )
                    )

            # Extensions target existing roles and reference existing permissions.
            for extension in document.role_extensions:
                if extension.role_id not in role_ids:
                    issues.append(
                        ValidationIssue(
                            IssueLevel.ERROR,
                            f"role_extension targets unknown role {extension.role_id!r}.",
                            sid,
                        )
                    )
                for perm_id in (*extension.add_permissions, *extension.remove_permissions):
                    if perm_id not in permission_index:
                        issues.append(
                            ValidationIssue(
                                IssueLevel.ERROR,
                                f"role_extension {extension.role_id} references unknown permission {perm_id!r}.",
                                sid,
                            )
                        )

        return issues

    def _collect_and_check_duplicates(
        self,
        documents: list[SchemaDocument],
        category_ids: set[str],
        permission_index: dict[str, tuple[str, ...]],
        role_ids: set[str],
    ) -> list[ValidationIssue]:
        """Populate the id indexes and flag conflicting/identical duplicates."""
        issues: list[ValidationIssue] = []
        categories: dict[str, object] = {}
        permissions: dict[str, object] = {}
        roles: dict[str, object] = {}

        for document in documents:
            sid = document.source.source_id
            for category in document.categories:
                issues.extend(self._register(categories, category.id, category, "category", sid))
                category_ids.add(category.id)
            for permission in document.permissions:
                issues.extend(self._register(permissions, permission.identifier, permission, "permission", sid))
                permission_index[permission.identifier] = permission.scopes
            for role in document.roles:
                issues.extend(self._register(roles, role.id, role, "role", sid))
                role_ids.add(role.id)
        return issues

    @staticmethod
    def _check_permission_dependencies(documents: list[SchemaDocument]) -> list[ValidationIssue]:
        """Check every ``depends_on`` entry and reject dependency cycles (ADR 0034 §3).

        A conflicting duplicate permission is already an error, so the first definition of each
        permission is the one checked.
        """
        definitions: dict[str, tuple[PermissionDefinition, str]] = {}
        for document in documents:
            for permission in document.permissions:
                definitions.setdefault(permission.identifier, (permission, document.source.source_id))

        issues: list[ValidationIssue] = []
        for perm_id, (permission, sid) in sorted(definitions.items()):
            for dependency_id in permission.depends_on:
                if dependency_id == perm_id:
                    continue  # Reported below as a cycle of one.
                dependency = definitions.get(dependency_id)
                if dependency is None:
                    issues.append(
                        ValidationIssue(
                            IssueLevel.ERROR,
                            f"Permission {perm_id} depends on unknown permission {dependency_id!r}.",
                            sid,
                        )
                    )
                    continue
                uncovered = set(permission.scopes) - set(dependency[0].scopes)
                if uncovered:
                    issues.append(
                        ValidationIssue(
                            IssueLevel.ERROR,
                            f"Permission {perm_id} supports scope(s) {sorted(uncovered)} "
                            f"that its dependency {dependency_id!r} does not support.",
                            sid,
                        )
                    )

        dependency_map = {perm_id: permission.depends_on for perm_id, (permission, _sid) in definitions.items()}
        for cycle in find_cycles(dependency_map):
            if len(cycle) == 1:
                message = f"Permission {cycle[0]} depends on itself."
            else:
                message = f"Permissions form a dependency cycle: {' -> '.join((*cycle, cycle[0]))}."
            issues.append(ValidationIssue(IssueLevel.ERROR, message, definitions[cycle[0]][1]))
        return issues

    def _check_role_dependencies(self, schema: CompiledSchema) -> list[ValidationIssue]:
        """A role must grant every direct and indirect dependency of its permissions (ADR 0034 §3).

        The check runs on the compiled roles, so it sees permissions added and removed by role
        extensions, and it applies to every file whatever ``schema_version`` it declares.
        """
        dependency_map = {perm_id: compiled.definition.depends_on for perm_id, compiled in schema.permissions.items()}
        issues: list[ValidationIssue] = []
        for role_id, compiled_role in sorted(schema.roles.items()):
            missing = missing_dependencies(compiled_role.definition.permissions, dependency_map)
            for perm_id, absent in missing.items():
                issues.append(
                    ValidationIssue(
                        IssueLevel.ERROR,
                        f"Role {role_id} grants permission {perm_id!r} without its dependencies {list(absent)}. "
                        f"Add them to the role, or keep role_extensions from removing them.",
                        self._role_permission_source_id(schema, role_id, perm_id),
                    )
                )
        return issues

    @staticmethod
    def _check_visible_dependencies(schema: CompiledSchema) -> list[ValidationIssue]:
        """Reject visible permissions that depend on hidden ones, directly or indirectly.

        A permission is hidden when it, or its category, is hidden (ADR 0038). Only direct
        dependencies are checked, which also covers indirect ones: any chain from a visible
        permission to a hidden one has a visible permission that directly depends on a hidden one.
        Unknown dependencies and categories are skipped, since other checks report them.
        """

        def is_hidden(perm_id: str) -> bool | None:
            compiled = schema.permissions.get(perm_id)
            if compiled is None:
                return None
            category = schema.categories.get(compiled.definition.category_id)
            return compiled.definition.hidden or bool(category and category.definition.hidden)

        issues: list[ValidationIssue] = []
        for perm_id, compiled in sorted(schema.permissions.items()):
            if is_hidden(perm_id):
                continue
            hidden_dependencies = sorted(dep for dep in compiled.definition.depends_on if is_hidden(dep))
            if hidden_dependencies:
                sources = compiled.sources
                issues.append(
                    ValidationIssue(
                        IssueLevel.ERROR,
                        f"Visible permission {perm_id} depends on hidden permission(s) {hidden_dependencies}. "
                        f"Hide the permission too, or make its dependencies visible.",
                        sources[0].source_id if sources else None,
                    )
                )
        return issues

    @staticmethod
    def _register(index: dict, key: str, value, kind: str, sid: str) -> list[ValidationIssue]:
        """Record a base definition, flagging duplicates.

        Identical duplicate → warning; conflicting duplicate → error.
        """
        if key not in index:
            index[key] = value
            return []
        if index[key] == value:
            return [ValidationIssue(IssueLevel.WARNING, f"Duplicate identical {kind} {key!r}.", sid)]
        return [ValidationIssue(IssueLevel.ERROR, f"Conflicting {kind} definition for {key!r}.", sid)]

    @staticmethod
    def _check_role_id_prefix(role_id: str, sid: str) -> list[ValidationIssue]:
        """Reject a static role ID that starts with the prefix reserved for custom roles (ADR 0035).

        The prefix is what keeps static and custom role IDs from colliding, so the check runs
        before any database change and names the source that declares the role.
        """
        if not role_id.startswith(CUSTOM_ROLE_ID_PREFIX):
            return []
        return [
            ValidationIssue(
                IssueLevel.ERROR,
                f"Role {role_id!r} uses the {CUSTOM_ROLE_ID_PREFIX!r} prefix, which is reserved for custom roles.",
                sid,
            )
        ]

    @staticmethod
    def _check_permissions(role_id: str, permissions: tuple[str, ...], sid: str) -> list[ValidationIssue]:
        """Warn when a role relies entirely on permissions from role extensions."""
        if permissions:
            return []
        return [
            ValidationIssue(
                IssueLevel.WARNING,
                f"role {role_id!r} declares no base permissions; role_extensions must contribute them.",
                sid,
            )
        ]

    @staticmethod
    def _check_role_permission_scope(
        role_id: str,
        perm_id: str,
        role_scopes: tuple[str, ...],
        permission_scopes: tuple[str, ...] | None,
        sid: str | None,
        *,
        missing_verb: str,
    ) -> list[ValidationIssue]:
        """Check one role-permission pairing: the permission exists and supports the role's scopes.

        ``permission_scopes`` is the permission's supported scopes, or ``None``
        when the permission does not exist. ``missing_verb`` is the phrase used
        for the unknown-permission message, so the pre-compile pass can say the
        role *references* a permission while the post-compile pass says it
        *resolves to* one.
        """
        if permission_scopes is None:
            return [
                ValidationIssue(
                    IssueLevel.ERROR,
                    f"Role {role_id} {missing_verb} unknown permission {perm_id!r}.",
                    sid,
                )
            ]
        unsupported = set(role_scopes) - set(permission_scopes)
        if unsupported:
            return [
                ValidationIssue(
                    IssueLevel.ERROR,
                    f"Role {role_id} is defined for scope(s) {sorted(unsupported)} "
                    f"that permission {perm_id!r} does not support.",
                    sid,
                )
            ]
        return []

    @staticmethod
    def _check_permission_category(
        perm_id: str,
        category_id: str,
        known_category_ids: Container[str],
        sid: str | None,
    ) -> list[ValidationIssue]:
        """A permission's category, when set, must reference an existing category."""
        if category_id and category_id not in known_category_ids:
            return [
                ValidationIssue(
                    IssueLevel.ERROR,
                    f"Permission {perm_id} references unknown category {category_id!r}.",
                    sid,
                )
            ]
        return []

    @staticmethod
    def _check_icon(value: str | None, context: str, sid: str) -> list[ValidationIssue]:
        """Validate an optional Paragon icon name (ADR 0017 §4).

        JSON Schema owns the value's type and format. This check verifies that
        the formatted name is one of the vendored ``@openedx/paragon/icons``
        exports (see :mod:`paragon_icons`, ``make paragon_icons``).
        """
        if not isinstance(value, str) or not value:
            return []
        if value not in PARAGON_ICON_NAMES:
            return [
                ValidationIssue(
                    IssueLevel.ERROR,
                    f"{context}: icon {value!r} is not a valid @openedx/paragon/icons name.",
                    sid,
                )
            ]
        return []

    @staticmethod
    def _role_permission_source_id(schema: CompiledSchema, role_id: str, perm_id: str) -> str | None:
        """Name the source(s) responsible for one role-permission grant.

        A role-permission grant is the link that assigns a permission to a role:
        a single ``(role_id, permission_id)`` pairing in the compiled schema. ADR
        0025 defines it as the atomic unit of attribution (one grant renders to
        one Casbin ``p`` row). It is distinct from a *role assignment*, which
        links a subject to a role (the ``g`` policies of ADR 0012). The grant's
        provenance is tracked on ``schema.role_permission_sources``; this returns
        the source id(s) to attribute a validation issue to.

        Prefers extension contributions: when an extension introduces the
        offending permission, the operator needs the extending file's id, not
        the file that declared the role.
        """
        sources = schema.role_permission_sources.get((role_id, perm_id), [])
        extensions = [src for src in sources if src.origin_kind == SchemaOriginKind.EXTENSION]
        chosen = extensions or sources
        if not chosen:
            return None
        return ", ".join(sorted({src.source.source_id for src in chosen}))

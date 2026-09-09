"""Validate schema documents individually and as a whole (the ``validate`` step).

Rules come from ADR 0017 §4 and the field reference:

Per-document checks:
    * ``schema_version`` is a supported, quoted ``major.minor`` value.
    * ``namespace``, ``name``, category ``id``, role ``id`` match
      :data:`IDENTIFIER_RE` (lowercase snake_case, begins with a letter).
    * Casbin forms (``act^...``, ``role^...``) are rejected as identifiers.
    * Required fields are present.
    * ``scopes`` are non-empty and look like scope namespaces (hyphens allowed,
      e.g. ``course-v1``); they are exempt from the identifier regex.

Whole-set checks (after all documents load):
    * Every permission ``category`` references an existing category.
    * Every role/extension permission references an existing permission.
    * A role's ``scopes`` are supported by each of its permissions.
    * ``role_extensions`` target an existing role (ADR 0023).
    * Conflicting duplicate base definitions fail; identical duplicates warn.

Validation collects issues rather than raising on the first problem, so the
deployment report can list every error and warning at once. No Casbin/Django
imports.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from openedx_authz.engine.schema.types import SchemaDocument

IDENTIFIER_RE = re.compile(r"^[a-z][a-z0-9_]*$")
# Scope namespaces follow their registered spelling and may contain hyphens.
SCOPE_RE = re.compile(r"^[a-z][a-z0-9_-]*$")

# Casbin-internal prefixes that must never appear in a schema identifier.
CASBIN_INTERNAL_PREFIXES = ("act^", "role^", "sub^", "scope^", "g^", "p^")

ERROR = "error"
WARNING = "warning"


@dataclass(frozen=True)
class ValidationIssue:
    """A single validation finding.

    Attributes:
        level: ``"error"`` (blocks deployment) or ``"warning"`` (reported only).
        message: Human-readable description.
        source_id: The contributing source, when the issue is file-specific.
    """

    level: str
    message: str
    source_id: str | None = None

    @property
    def is_error(self) -> bool:
        return self.level == ERROR


class SchemaValidator:
    """Runs per-document and whole-set validation."""

    SUPPORTED_SCHEMA_VERSIONS = frozenset({"1.0"})

    # ---- entry points -----------------------------------------------------

    def validate(self, documents: list[SchemaDocument]) -> list[ValidationIssue]:
        """Run per-document then whole-set validation, returning all issues."""
        issues: list[ValidationIssue] = []
        for document in documents:
            issues.extend(self.validate_document(document))
        issues.extend(self.validate_set(documents))
        return issues

    @staticmethod
    def has_errors(issues: list[ValidationIssue]) -> bool:
        """True if any issue is error-level."""
        return any(issue.is_error for issue in issues)

    # ---- per-document -----------------------------------------------------

    def validate_document(self, document: SchemaDocument) -> list[ValidationIssue]:
        """Per-file checks that need no cross-file context."""
        issues: list[ValidationIssue] = []
        sid = document.source.source_id

        if document.source.schema_version not in self.SUPPORTED_SCHEMA_VERSIONS:
            issues.append(
                ValidationIssue(
                    ERROR,
                    f"Unsupported schema_version {document.source.schema_version!r}; "
                    f"supported: {sorted(self.SUPPORTED_SCHEMA_VERSIONS)}.",
                    sid,
                )
            )

        for category in document.categories:
            issues.extend(self._check_identifier(category.id, "category id", sid))
            issues.extend(self._require(category.id, "category id", sid))

        for permission in document.permissions:
            issues.extend(self._check_identifier(permission.namespace, "permission namespace", sid))
            issues.extend(self._check_identifier(permission.name, "permission name", sid))
            issues.extend(self._require(permission.category, f"category for {permission.identifier}", sid))
            issues.extend(self._check_scopes(permission.scopes, f"permission {permission.identifier}", sid))

        for role in document.roles:
            issues.extend(self._check_identifier(role.id, "role id", sid))
            issues.extend(self._check_scopes(role.scopes, f"role {role.id}", sid))
            for perm_id in role.permissions:
                issues.extend(self._check_permission_id(perm_id, f"role {role.id}", sid))

        for extension in document.role_extensions:
            issues.extend(self._check_identifier(extension.role, "role_extension target", sid))
            for perm_id in (*extension.add_permissions, *extension.remove_permissions):
                issues.extend(self._check_permission_id(perm_id, f"role_extension {extension.role}", sid))

        return issues

    # ---- whole-set --------------------------------------------------------

    def validate_set(self, documents: list[SchemaDocument]) -> list[ValidationIssue]:
        """Whole-set checks across all loaded documents."""
        issues: list[ValidationIssue] = []

        category_ids: set[str] = set()
        permission_index: dict[str, tuple[str, ...]] = {}  # id -> scopes
        role_ids: set[str] = set()

        issues.extend(self._collect_and_check_duplicates(documents, category_ids, permission_index, role_ids))

        # Reference integrity: permission categories exist.
        for document in documents:
            sid = document.source.source_id
            for permission in document.permissions:
                if permission.category and permission.category not in category_ids:
                    issues.append(
                        ValidationIssue(
                            ERROR,
                            f"Permission {permission.identifier} references unknown category "
                            f"{permission.category!r}.",
                            sid,
                        )
                    )

            # Role permissions exist, and role scopes are supported by each permission.
            for role in document.roles:
                for perm_id in role.permissions:
                    if perm_id not in permission_index:
                        issues.append(
                            ValidationIssue(
                                ERROR,
                                f"Role {role.id} references unknown permission {perm_id!r}.",
                                sid,
                            )
                        )
                        continue
                    unsupported = set(role.scopes) - set(permission_index[perm_id])
                    if unsupported:
                        issues.append(
                            ValidationIssue(
                                ERROR,
                                f"Role {role.id} is defined for scope(s) {sorted(unsupported)} "
                                f"that permission {perm_id!r} does not support.",
                                sid,
                            )
                        )

            # Extensions target existing roles and reference existing permissions.
            for extension in document.role_extensions:
                if extension.role not in role_ids:
                    issues.append(
                        ValidationIssue(
                            ERROR,
                            f"role_extension targets unknown role {extension.role!r}.",
                            sid,
                        )
                    )
                for perm_id in (*extension.add_permissions, *extension.remove_permissions):
                    if perm_id not in permission_index:
                        issues.append(
                            ValidationIssue(
                                ERROR,
                                f"role_extension {extension.role} references unknown permission {perm_id!r}.",
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
    def _register(index: dict, key: str, value, kind: str, sid: str) -> list[ValidationIssue]:
        """Record a base definition, flagging duplicates.

        Identical duplicate → warning; conflicting duplicate → error.
        """
        if key not in index:
            index[key] = value
            return []
        if index[key] == value:
            return [ValidationIssue(WARNING, f"Duplicate identical {kind} {key!r}.", sid)]
        return [ValidationIssue(ERROR, f"Conflicting {kind} definition for {key!r}.", sid)]

    # ---- helpers ----------------------------------------------------------

    def _check_identifier(self, value: str, label: str, sid: str) -> list[ValidationIssue]:
        """Validate a single identifier is lowercase snake_case and not a Casbin form."""
        if not value:
            return []  # emptiness handled by _require where relevant
        if any(value.startswith(prefix) for prefix in CASBIN_INTERNAL_PREFIXES):
            return [ValidationIssue(ERROR, f"{label} {value!r} uses an internal Casbin form.", sid)]
        if not IDENTIFIER_RE.match(value):
            return [
                ValidationIssue(
                    ERROR,
                    f"{label} {value!r} must match {IDENTIFIER_RE.pattern} (lowercase snake_case).",
                    sid,
                )
            ]
        return []

    def _check_permission_id(self, value: str, context: str, sid: str) -> list[ValidationIssue]:
        """A complete permission id is ``namespace.name`` with both parts valid."""
        if value.count(".") != 1:
            return [
                ValidationIssue(
                    ERROR,
                    f"{context}: permission id {value!r} must be 'namespace.name'.",
                    sid,
                )
            ]
        namespace, name = value.split(".", 1)
        issues = self._check_identifier(namespace, f"{context} permission namespace", sid)
        issues += self._check_identifier(name, f"{context} permission name", sid)
        return issues

    def _check_scopes(self, scopes: tuple[str, ...], context: str, sid: str) -> list[ValidationIssue]:
        """Validate that at least one scope is declared and each scope namespace is well-formed."""
        if not scopes:
            return [ValidationIssue(ERROR, f"{context} must declare at least one scope.", sid)]
        issues: list[ValidationIssue] = []
        for scope in scopes:
            if not SCOPE_RE.match(scope):
                issues.append(
                    ValidationIssue(ERROR, f"{context}: invalid scope namespace {scope!r}.", sid)
                )
        return issues

    @staticmethod
    def _require(value: str, label: str, sid: str) -> list[ValidationIssue]:
        if not value:
            return [ValidationIssue(ERROR, f"Missing required field: {label}.", sid)]
        return []

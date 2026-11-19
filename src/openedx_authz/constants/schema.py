"""Shared constants for the static authorization schema (ADR 0023/0025).

This is the single source of truth for the ``base`` / ``extension`` origin
values. ``SchemaOriginKind`` is a plain ``str`` enum with no Django or Casbin
dependency, so both the engine schema types
(``openedx_authz.engine.schema.types``) and the Django models layer
(``openedx_authz.models.schema.OriginKind``) can share the same values without
either layer depending on the other.
"""

from __future__ import annotations

from enum import Enum

AUTHZ_JSON_SCHEMA_SETTING = "OPENEDX_AUTHZ_JSON_SCHEMA"
DEFAULT_AUTHZ_JSON_SCHEMA = "openedx_authz.engine.schema/authz-schema-v1.json"

CUSTOM_ROLE_ID_PREFIX = "custom_"
CUSTOM_ROLE_ID_MAX_LENGTH = 64


class DefinitionKind(str, Enum):
    """How a role is defined (ADR 0028, ADR 0035).

    ``STATIC`` roles come from the authorization schema and are managed by the schema loader.
    ``USER_DEFINED`` roles are custom roles created by administrators; the loader never touches
    them. Subclassing ``str`` keeps the members interchangeable with the raw values stored in the
    database.
    """

    STATIC = "static"
    USER_DEFINED = "user_defined"


class SchemaOriginKind(str, Enum):
    """Whether a schema contribution is a base definition or an extension.

    ``BASE`` comes from a role's own definition; ``EXTENSION`` is added by a
    ``role_extensions`` entry (ADR 0023/0025). Subclassing ``str`` keeps the
    members interchangeable with their raw string values, which is why the
    persistence layer can store them directly.
    """

    BASE = "base"
    EXTENSION = "extension"

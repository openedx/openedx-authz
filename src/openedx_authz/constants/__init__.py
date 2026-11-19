"""Shared low-level constants for openedx_authz.
Defined here rather than in api.data so that models and other modules at the
bottom of the import chain can use them without creating circular imports.
"""

from openedx_authz.constants.schema import (
    CUSTOM_ROLE_ID_MAX_LENGTH,
    CUSTOM_ROLE_ID_PREFIX,
    DefinitionKind,
    SchemaOriginKind,
)

AUTHZ_POLICY_ATTRIBUTES_SEPARATOR = "^"

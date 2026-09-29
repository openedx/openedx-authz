"""Shared low-level constants for openedx_authz.

Defined here rather than in api.data so that models and other modules at the
bottom of the import chain can use them without creating circular imports.
"""

AUTHZ_POLICY_ATTRIBUTES_SEPARATOR = "^"

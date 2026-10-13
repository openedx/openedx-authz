"""REST API views built for the Admin Console's specific workflows.

These endpoints operate on Authorization's own data (roles, permissions,
assignments, scopes), but their shape is built around one consumer's screens
rather than being reusable as-is by any caller. Decision item 4 in ADR 0026
places them in a consumer-specific subpackage for data that still belongs to
Authorization.
"""

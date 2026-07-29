"""REST API views built for the Admin Console's specific workflows.

These endpoints operate on Authorization's own data (roles, permissions,
assignments, scopes), but their shape is built around one consumer's screens
rather than being reusable as-is by any caller. This is decision item 2 in ADR
0017 (rest-api-package-layout-convention), a consumer-specific subpackage for
data that still belongs to Authorization. See ADR 0016 for the domain-ownership
reasoning this rests on.
"""

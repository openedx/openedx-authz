"""Internal API for policy management.

A policy in Casbin defines the access control rules. It specifies which subject
(user, role, or group) can perform which action on which object (resource) under
a given context.
Policies are stored in the policy store (CSV file, DB, or adapter) and are
enforced by Casbin's engine ../engine/enforcer.py.

Since a policy specifies roles, role's permissions, and assignments, this module
will be an internal API used by the roles and permissions modules to manage
their definitions.
"""

from django.db.models import QuerySet
from openedx_authz.engine.enforcer import enforcer
from openedx_authz.engine.filter import Filter

# TODO: should this be cached and called for each request depending on the user?
def get_policies(filter: Filter) -> QuerySet:
    """Get all policies from the policy store.

    Returns:
        list[str]: The policies. A list of strings, each string is a policy
        rule. The policy rule is a string of the form 'sub, act, obj, eft'. For
        example:
            [
                ['role:platform_admin', 'act:manage', '*', 'allow'],
                ['role:org_admin', 'act:manage', 'lib:*', 'allow'],
                ['role:org_editor', 'act:edit', 'lib:*', 'allow'],
                ['role:library_author', 'act:edit', 'lib:*', 'allow'],
                ['role:library_reviewer', 'act:read', 'lib:*', 'allow'],
                ['role:editor', 'act:edit', 'lib:*', 'allow'],
                ['role:report_viewer', 'act:read', 'report:*', 'allow'],
            ].
    """
     # TODO: This should be a queryset that's evaluated only when enforcing
     # Here we have a filter that we should turn into Q objects to load
     # a qs into memory
     # Debemos probar que método de cache tiene mejor performance: org, user, SAOC
    return enforcer.load_filtered_policy(filter)

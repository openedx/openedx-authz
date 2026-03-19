0012: Glob Support For Role Assignments
#######################################

Status
******

**Draft** - *2026-03-18*

Context
*******

The current authorization system is based on Casbin and models:

- **Permissions per role** (``p`` policies), where the ``scope`` field may already use patterns (for example, ``lib^*``) through matcher functions in the model.
- **Role assignments** (``g`` policies), which link a subject to a role within a scope.

The current Casbin model treats the ``scope`` field in ``g`` policies as an **exact match**. This is sufficient when roles are granted for a single, concrete scope value, but it is limiting when operators need to:

- Assign roles that are valid for a **set of resources** that share a common prefix (for example, all courses or all content libraries belonging to a given organization).
- Avoid enumerating a large or evolving set of resources one by one, which increases operational overhead and risk of drift.

This ADR proposes enabling glob-like matching for role assignments, so that a single ``g`` policy can represent a multi-scope assignment such as:

.. code:: text

   g, user^contributor, role^course_staff, course-v1^course-v1:OpenedX+*

In that example, checking a permission such as:

.. code:: text

   authz_api.is_user_allowed("contributor", "courses.manage_advanced_settings", "course-v1:OpenedX+Some+Course")

should be allowed if the user's role assignment matches the ``course-v1:OpenedX+*`` pattern.

At the same time, we must preserve the guarantees of the authorization model:

- **Safety**: Glob patterns must not accidentally grant permissions outside of the intended boundary.
- **Clarity**: Patterns must be easy to understand and reason about for operators and auditors.
- **Extensibility**: The mechanism should be general enough to support future use cases without requiring a redesign of the model.

Decision
********

We will introduce support for glob-like matching on the ``scope`` field of **role assignments** (``g`` policies), combined with explicit validation in the public APIs that manage those assignments.

The decision is intentionally **general**: the core change is to allow glob matching for scopes in ``g`` policies, and to guard its usage with well-defined, namespace-specific validation rules. This creates a foundation that can be extended later without changing the Casbin model again.

1. Enable glob matching on ``g`` scopes in the enforcer
=======================================================

We will configure the ``AuthzEnforcer`` to use a domain/scope matching function for ``g`` policies that supports glob-like suffixes. Concretely:

- The enforcer will register a domain matching function for the ``g`` (grouping) function (for example, using ``key_match_func``).
- This matching function will treat ``*`` as a wildcard at the **end** of the string. That is, patterns such as ``course-v1:OpenedX+*`` will match ``course-v1:OpenedX+SOME+COURSE``, but the model will not rely on complex patterns or regular expressions.
- Existing ``g`` policies that use exact scopes remain valid and continue to behave identically.

This change allows the Casbin engine to evaluate role assignments that apply to a family of scopes instead of a single exact value, without modifying the underlying storage schema (``CasbinRule``) or the overall request format (``r = sub, act, scope``).

2. Validate glob scopes at the API boundary
===========================================

All APIs that create, update, or delete role assignments (i.e., policies of type ``g``) must validate any scope that includes a glob pattern. The goals of validation are:

- **Constrain** what forms of glob are permitted for each namespace.
- **Reject** malformed or overly broad patterns that would be difficult to reason about or audit.

The following rules apply initially:

- The glob character (``*``) is only supported as a **suffix wildcard**. It cannot appear in the middle of a scope identifier.
- A glob pattern represents a **bounded prefix match** for the external key portion of a scope within its namespace. The API validation ensures the prefix is meaningful (i.e., it corresponds to a valid identifier boundary for that namespace), so the glob cannot be used to accidentally broaden access.
- For any glob patterns (courses, libraries, or future namespaces), malformed inputs (such as mid-string wildcards or prefixes that do not match the expected key format/boundaries) are **rejected**.
- Additional namespaces must define their own, explicit validation rules before accepting glob scopes.
- As needs evolve, more glob types can be added safely by introducing namespace-specific semantics and validations (for example, additional prefix boundaries such as program/tenant prefixes, or narrower matching strategies if required).

These validation rules are implemented in the Open edX layer (API / data layer), not in the Casbin matcher itself. The enforcer remains general-purpose. The domain-specific semantics of what constitutes an acceptable glob pattern are enforced at the boundary where user/operator input is turned into policies.

3. Keep the model general and extensible
========================================

By introducing glob support in role assignments in a constrained way, we unlock a set of future extensions without redesigning the model:

- **Other scope types**

  - Scope types with hierarchical or prefix-based identifiers (for example, libraries or other content groupings) can adopt glob support by:

    - Defining their own namespace-specific rules for valid suffix globs.
    - Reusing the same enforcer-level domain matching capability.

- **Future matching strategies**

  - If, in the future, there is a strong need for more expressive matching (for example, segment-based matching or multiple wildcards), these can be introduced as **new, explicitly-scoped features** with their own validation rules and migration story.
  - For now, we deliberately keep glob support simple and limited (single trailing ``*``) to minimize complexity and security risk.

Consequences
************

Positive consequences
=====================

- **Increased expressiveness**: Operators can express multi-scope role assignments (for example, "course staff for all courses in organization OpenedX") without enumerating each course in individual ``g`` policies.
- **Reduced operational overhead**: New resources that fall under an existing glob pattern automatically inherit the appropriate role assignments, reducing the need for ongoing manual updates.
- **Better alignment with real-world use cases**: Many organizational setups naturally require "all resources under this prefix" semantics. Glob support maps directly to those needs.
- **Clear extension path**: The mechanism is generic enough to be reused for other namespaces (such as organization or library scopes), as long as each namespace defines and enforces its own validation rules.

Negative consequences / risks
=============================

- **Security and safety**: If validation is misconfigured or bypassed, glob patterns could unintentionally grant access beyond the intended boundary. This risk is mitigated by:

  - Enforcing validation in the Open edX API layer.
  - Restricting globs to trailing ``*`` patterns.
  - Defining precise, namespace-specific rules.

- **Complexity in mental model**: Operators and developers must understand that some role assignments apply to families of scopes instead of a single scope. This can be addressed by:

  - Providing clear documentation and examples for glob-based assignments.
  - Exposing introspection tooling that explains which policies matched a given decision.

- **Performance considerations**: Glob matching adds some overhead to Casbin evaluations. However:

  - The cost of simple suffix matching is low.
  - The policy store still uses the same schema and indexing strategy.
  - The feature should be used primarily for coarse-grained groupings (e.g., by organization), not for highly fragmented patterns.

Rejected Alternatives
**********************

- **Keep exact matching only for 'g' scopes**

  - Pros:

    - Simpler to reason about.
    - No changes to matcher configuration.
  - Cons:

    - Does not scale for environments with many resources per organization.
    - Forces operators to maintain large numbers of nearly-identical assignments.

- **Introduce full regular-expression support on scopes**

  - Pros:

    - Maximum flexibility for expressing patterns.
  - Cons:

    - Harder to reason about and audit.
    - Higher risk of misconfiguration and security overshoot.
    - Potentially worse performance.

References
**********

- `Casbin function documentation (matching functions) <https://casbin.org/docs/function/>`_

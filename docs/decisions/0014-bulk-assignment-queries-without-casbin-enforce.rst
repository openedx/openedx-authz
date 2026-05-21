0014: Visible Role Assignment Queries Without Casbin Enforce Calls
##################################################################

Status
******

**Accepted** - *2026-05-19*

Context
*******

``get_visible_role_assignments_for_user`` and ``get_visible_user_role_assignments_filtered_by_current_user``
are the main entry points for listing role assignments in the admin console. Both answer two questions:

1. Which assignments match the requested filters (org, scope, role)?
2. Which of those assignments is the requesting user allowed to see?

The original implementation answered question 2 by calling ``is_user_allowed`` once per candidate
assignment. Internally, ``is_user_allowed`` calls ``enforcer.enforce()``, which evaluates the full
Casbin policy graph for a single (subject, action, object) triple. With N assignments in scope,
this means N Casbin enforce calls in the hot path.

Additionally, the two questions were answered in the wrong order: question 2 (authorization) ran
first on the full assignment list, and question 1 (filtering) ran afterward on the grouped result.
Assignments that would have been dropped by the filter were still evaluated by Casbin.

Decision
********

Avoid Casbin ``enforce()`` in the visible-assignment hot path. The authorization check is replaced
by a scope-based approach that retrieves the viewer's accessible scopes from the database and
matches assignment scopes in Python.

#. Replace per-assignment enforce() with scope lookups
=======================================================

A new public function, ``filter_role_assignments_visible_to_subject`` (in
``openedx_authz.api.roles``), replaces per-assignment ``enforce()`` calls. It:

- calls ``get_scopes_for_subject_and_permission`` once per distinct permission type across all
  candidates (one DB query per type),
- uses Casbin's own ``key_match_func`` to check whether each assignment's scope matches any of
  the viewer's accessible scopes.

The number of DB queries is bounded by the number of distinct permission types, not the number
of assignments. No Casbin enforce calls are made in the common path.

#. Filter by params before the authorization pass
==================================================

A new ``_filter_assignments_by_params`` function applies org, scope, and role filters on the
flat assignment list before the authorization pass. Assignments that would be dropped by the
filters are never evaluated for visibility. The order is now: filter cheaply, then authorize.

#. Cache role permission lookups within a call
===============================================

``get_role_assignments`` now caches ``get_permissions_for_single_role`` results within a single
call using a local ``_perm_cache`` dict. When multiple assignments share the same role key, the
permission list is resolved once instead of once per policy entry.

Consequences
************

#. **The number of Casbin enforce calls in the visible-assignment path drops to zero** for the
   common case. The number of DB queries is proportional to the number of distinct permission
   types, not the number of assignments.

#. **Pre-filtering reduces the authorization surface.** Both the authorization pass and the
   subsequent grouping step operate on a smaller list.

#. **``filter_role_assignments_visible_to_subject`` is a public function** in
   ``openedx_authz.api.roles``, available to callers who need visibility filtering outside of
   the user-assignment endpoints.

#. **``key_match_func`` is used directly from ``casbin.util``.** This couples the visibility
   filter to Casbin's matching semantics. If the model's matching behavior changes, this function
   must change too.

#. **The scope-based approach assumes ``get_scopes_for_subject_and_permission`` is correct
   and up-to-date.** If the enforcer cache is stale, the visibility filter will produce wrong
   results silently. The per-assignment ``enforce()`` approach had the same dependency, but
   made it implicit per call rather than resolved once upfront.

What We Have Learned About Casbin Performance
*********************************************

These patterns apply to any bulk query path that touches the Casbin enforcer.

**Prefer scope lookups over enforce loops.**
If the question is "can this user see any of these N items?", the right query is "what scopes
does this user have access to?", answered once, not "can this user access scope X?" answered N
times. ``get_scopes_for_subject_and_permission`` exists for this purpose.

**batch_enforce is an optimization, not a redesign.**
``batch_enforce`` removes per-call overhead but still evaluates N policies, one per item. It
is useful when a small number of enforce calls cannot be avoided. It is not a substitute for
rethinking the authorization strategy when N scales with user-controlled data.

**Use Casbin's own matching utilities.**
``casbin.util.key_match_func`` implements the same glob-matching logic as the Casbin model's
``keyMatch`` function. When you need to replicate Casbin's matching behavior in Python, use this
function rather than reimplementing it.

**Filter early, authorize late.**
Apply cheap, deterministic filters (field equality, list membership) before paying the cost of
authorization. Casbin is not involved in the first pass.

Alternatives Considered
***********************

``batch_enforce`` to replace the per-assignment loop
=====================================================

Replacing the ``enforce()`` loop with a single ``batch_enforce`` call was implemented first
(see ``528b129``). It removed the per-call overhead but kept N policy evaluations. For large
assignment lists the complexity does not change. Dropped in favor of the scope-based approach.

Per-assignment ``enforce()`` (original)
========================================

The original implementation was correct and simple. It was retained up to this point because
the visible-assignment endpoints were not on a measured hot path. Profiling under realistic
data volumes showed N enforce calls as the dominant cost. Replaced by this decision.

References
**********

- `ADR 0005`_
- `ADR 0012`_

.. _ADR 0005: https://github.com/openedx/openedx-authz/blob/main/docs/decisions/0005-architecture-and-data-modeling.rst
.. _ADR 0012: https://github.com/openedx/openedx-authz/blob/main/docs/decisions/0012-auditability.rst

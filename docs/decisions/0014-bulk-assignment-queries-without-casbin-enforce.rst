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

The original implementation called ``is_user_allowed`` once per candidate assignment.
``is_user_allowed`` calls ``enforcer.enforce()``, one policy evaluation per call. With N
assignments, that is N enforce calls per request, which is too expensive at realistic data volumes.

The two questions were also answered in a different order: question 2 (authorization) ran first on
the full assignment list, and question 1 (filtering) ran afterward on the grouped result.
Assignments that would have been dropped by the filter were still evaluated by Casbin.

Decision
********

Avoid Casbin ``enforce()`` in the visible-assignment hot path. Instead, retrieve the viewer's
accessible scopes from the database and match assignment scopes in Python.

#. Replace per-assignment enforce() with scope lookups
=======================================================

A new public function, ``filter_role_assignments_visible_to_subject`` (in
``openedx_authz.api.roles``), replaces per-assignment ``enforce()`` calls. It:

- calls ``get_scopes_for_subject_and_permission`` once per distinct permission type across all
  candidates (one DB query per type),
- uses Casbin's own ``key_match_func`` to check whether each assignment's scope matches any of
  the viewer's accessible scopes.

This reduces DB queries from N (one per assignment) to M (one per distinct permission type, typically 1-3) and moves the
matching logic into Python. The function is public for reuse in other contexts where visibility filtering is needed.

#. Filter by params before the authorization pass
==================================================

A new ``_filter_assignments_by_params`` function applies org, scope, and role filters on the
flat assignment list before the authorization pass. Assignments that would be dropped by the
filters are never evaluated for visibility.

#. Cache role permission lookups within a call
===============================================

``get_role_assignments`` now uses a local ``_perm_cache`` dict to avoid calling
``get_permissions_for_single_role`` more than once per role key per call.

Consequences
************

#. **No Casbin enforce calls in the visible-assignment for filtering** This is the main point of the change, improving performance by reducing per-assignment overhead.

#. **The authorization pass and grouping step operate on a pre-filtered list.** Assignments
   dropped by the filters are never evaluated for visibility.

#. **``filter_role_assignments_visible_to_subject`` is a public function** in
   ``openedx_authz.api.roles``, available to callers who need visibility filtering outside of
   the user-assignment endpoints.

#. **``key_match_func`` is used directly from ``casbin.util``.** This couples the visibility
   filter to Casbin's matching semantics. If the model's matching behavior changes, this function
   must change too.

#. **``get_scopes_for_subject_and_permission`` must return current data.** If the enforcer cache
   is stale, the visibility filter produces wrong results silently. The per-assignment
   ``enforce()`` approach had the same dependency, resolved per call rather than once upfront.

Patterns for Bulk Authorization Paths
**************************************

While implementing this change, we identified some patterns for bulk authorization paths like this one:

**Scope lookups for bulk visibility checks.**
Query the viewer's accessible scopes once rather than calling enforce per item.
``get_scopes_for_subject_and_permission`` does this.

**batch_enforce to reduce per-call overhead**
If per-item enforce calls are still needed, use Casbin's ``batch_enforce`` to reduce overhead getting the enforcer.
This was implemented and tested but ultimately not used in this case since scope lookups were sufficient.

**Use Casbin's own matching utilities.**
``casbin.util.key_match_func`` implements the same glob-matching logic as the Casbin model's
``keyMatch``. Use it rather than reimplementing the matching logic.

**Filter before authorizing.**
Apply cheap filters (field equality, etc.) before authorization. Casbin is not
involved in the first pass.

Alternatives Considered
***********************

``batch_enforce`` to replace the per-assignment loop
=====================================================

Replacing the ``enforce()`` loop with a single ``batch_enforce`` call was implemented first
(see `528b129`_). It removed per-call overhead but kept N policy evaluations. Dropped in favor
of the scope-based approach.

Short circuiting for admin users
=================================


References
**********

- `ADR 0005`_
- `ADR 0012`_

.. _ADR 0005: https://github.com/openedx/openedx-authz/blob/main/docs/decisions/0005-architecture-and-data-modeling.rst
.. _ADR 0012: https://github.com/openedx/openedx-authz/blob/main/docs/decisions/0012-auditability.rst
.. _528b129: https://github.com/openedx/openedx-authz/commit/528b129c829df13588e74965b1f8116d73320627

0025: Track the Source of Compiled Authorization Definitions
############################################################

Status
******

**Draft**

Context
*******

`ADR 0019`_ discovers static schema resources from multiple applications and `ADR 0018`_
compiles them into policy rows during deployment. Several requirements need to know *where*
each compiled definition came from:

* Multiple applications may contribute to the same role. When a module adds a permission to a
  built-in role (for example ``courses.export_grades`` on ``course_admin``), the system must be
  able to tell the core-provided grants apart from the module-provided grant even though both
  live in the same role.
* Operators and developers benefit from seeing which application contributed a role or
  permission, for debugging and auditing.
* A future capability to remove an application should be able to drop only the definitions that
  application provided, while shared definitions remain.

Today none of this is stored. Compiled definitions exist only as Casbin ``p`` rows, which encode
``role, action, scope, effect`` and carry no display metadata and no origin.

Two representations are possible for the origin: an extra field on the Casbin policy row, or a
value held only in the in-memory registry. Both were rejected. A policy-row field cannot hold
more than one contributing source, risks interfering with the enforcement matcher, and cannot
attribute display metadata or categories, which are not policy rows. An in-memory value does not
survive restarts, cannot be shared across processes, and cannot support idempotent re-deploys or
future removal.

Decision
********

1. Store compiled definitions and their sources in dedicated tables
====================================================================

The schema loader persists compiled definitions in first-class tables owned by ``openedx-authz``.
Casbin ``p`` rows remain the enforcement representation and are rendered from these tables in the
same transaction; the definition tables are the authoritative record that the API reads and that
deployment diffs.

The definition tables are:

* a permission-category table (stable id and display fields);
* a permission-definition table (namespace and name forming the complete permission id, plus
  display fields, category, and supported scopes);
* a role-definition table (stable role id, display fields, supported scopes, and the ``hidden``
  flag from `ADR 0023`_); and
* a role-permission table holding one row per ``(role, permission, scope)`` relationship.

The role-permission relationship is the atomic unit of attribution, because it corresponds one
to one with a rendered ``p`` row and is where role extensions take effect.

2. Attribute sources through an explicit many-to-many link
===========================================================

A source table records each distinct contribution. Its identity is ``(distribution, module)`` —
the installed distribution and the Python module that owns the resource. The file path is stored
as a non-identifying attribute only, so moving a definition between files within the same module
does not change its source and produces no add/remove churn. A content digest may be recorded for
diagnostics, but change detection relies on diffing compiled definitions rather than on the
digest, so the digest is advisory.

Every definition and every role-permission relationship links to one or more sources through
explicit link tables. Each link records whether the contribution was a base definition or an
extension, and the contributing file's priority so the winning metadata source is derivable. The
common case is a single link; the many-to-many exists to represent shared ownership and to make
removal precise.

All sources are treated equally. ``openedx-authz`` is a schema provider like any other
distribution, so there is no core-versus-module flag; callers that care about a particular origin
compare the distribution name directly.

3. Extending a built-in role keeps both origins distinct
========================================================

Because attribution lives at the role-permission grain, a core grant and a module-added grant on
the same role remain individually attributed. For ``course_admin``:

* the role definition links to the distribution that defines it, as a base contribution;
* each core permission links to that same distribution as a base contribution; and
* ``courses.export_grades`` links to the contributing module as an extension.

The two coexist in one role, yet each relationship row carries its own origin. If two applications
add the same permission to the same role, the single relationship row gains two source links.

4. Attribution is queryable and may be exposed by the API
=========================================================

Given any role or permission, its origin can be queried from the definition and link tables — for
a role as a whole, for a single permission, or for a specific role-permission grant. The
authorization definition API (`ADR 0021`_) may expose these sources so a client such as the
Administrative Console can show which application contributed a role or permission. Exposing the
sources is an additive, optional API change and is not required by this decision.

5. Metadata changes update definitions in place
================================================

When a source file changes a display name, description, icon, or similar field, the next
deployment recompiles and updates the existing definition row, keyed by its stable identifier. No
new definition row is created and relationships and assignments are unaffected.

6. Adopt pre-existing policy rows; leave unmanaged rows untouched
=================================================================

On the first deployment after this feature ships, existing Casbin ``p`` rows are adopted rather
than duplicated: for each rendered ``(role, permission, scope)`` that already exists as a policy
row without a definition record, the loader creates the definition and relationship rows and links
them to the contributing source. A pre-existing policy row that no schema declares is left in place
and enforceable, but is not attributed and does not appear in the definition tables. Pruning such
unmanaged rows is out of scope.

Consequences
************

* Compiled definitions, including display metadata that previously had no home, are persisted and
  readable through the API.
* The origin of any role, permission, or individual role-permission grant is queryable, and core
  and module contributions to the same role remain distinguishable.
* Moving a definition between files in the same module does not change its recorded source.
* Removing an application becomes tractable: relationships and definitions whose only source is the
  removed application can be pruned, while shared ones remain. Removal itself remains out of scope
  and follows the assignment-safety rules of `ADR 0018`_.
* The existing ``ExtendedCasbinRule`` model is not reused; it continues to describe role
  assignments (``g`` rows), while the new tables own definitions and provenance.
* Compilation must track provenance at the role-permission grain, and the apply step writes the
  definition, relationship, and source tables in the same transaction as the policy rows.

References
**********

* `ADR 0017`_
* `ADR 0018`_
* `ADR 0019`_
* `ADR 0021`_
* `ADR 0023`_

.. _ADR 0017: 0017-static-authorization-schema.rst
.. _ADR 0018: 0018-authorization-schema-lifecycle.rst
.. _ADR 0019: 0019-authorization-schema-discovery.rst
.. _ADR 0021: 0021-authorization-definition-api.rst
.. _ADR 0023: 0023-extend-static-roles.rst

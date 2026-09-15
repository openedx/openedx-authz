0025: Track the Source of Compiled Static Authorization Definitions
###################################################################

Status
******

**Draft**

Context
*******

.. note::

   This ADR concerns only **static** authorization definitions — roles and permissions declared in
   YAML schema files and compiled into policy rows during deployment. It does not cover **dynamic**
   definitions created at runtime through the API or written directly to the database. Source
   tracking for dynamically created definitions, if needed, is out of scope and left to a future
   decision.

`ADR 0019`_ discovers static schema resources from multiple applications and `ADR 0018`_
compiles them into policy rows during deployment. Several requirements need to know *where*
each compiled definition came from:

* Multiple applications may contribute to the same role. When a module adds a permission to a
  pre-existing role (for example ``courses.export_grades`` on ``course_admin``), the system must be
  able to tell the grants apart between the modules that defined them, even though both
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

Reusing the existing ``ExtendedCasbinRule`` model was also considered and rejected. It was an
early candidate, but it is geared toward role assignments (``g`` rows) and is one-to-one with its
corresponding ``CasbinRule``. Schema source tracking has the opposite shape: a single role or
permission can have more than one contributing source, which a one-to-one model cannot represent.
Overloading a model built for assignments to also carry definition provenance would blur two
distinct concerns; keeping them separate leaves ``ExtendedCasbinRule`` focused on assignments and
gives definitions dedicated tables.

Decision
********

1. Store compiled definitions and their sources in dedicated tables
====================================================================

The schema loader persists definitions compiled from static YAML schemas in first-class tables
owned by ``openedx-authz``. Casbin ``p`` rows remain the enforcement representation and are rendered
from these tables in the same transaction; the definition tables are the authoritative record that
the API reads and that deployment diffs.

The definition tables are:

* a **permission-category** table — a stable category id and display fields (display name,
  description, icon). Categories group permissions for display and grant no access on their own;
* a **permission-definition** table — the complete permission id (a namespace and a name), display
  fields, its category, and the supported scopes;
* a **role-definition** table — a stable role id, display fields, supported scopes, and the
  ``hidden`` flag from `ADR 0023`_; and
* a **role-permission** table — one row per ``(role, permission, scope)`` grant, relating a role
  definition and a permission definition.

The role-permission relationship is the atomic unit of attribution, because it corresponds one
to one with a rendered ``p`` row and is where role extensions take effect.

2. Attribute sources through an explicit many-to-many link
===========================================================

A **source** table records each distinct contribution. Its identity is ``(distribution, module)`` —
the installed distribution and the code module that owns the resource. The resource path is stored
as a non-identifying attribute only, so moving a definition between files within the same module
does not change its source and produces no add/remove churn. A content digest may be recorded for
diagnostics, but change detection relies on diffing compiled definitions rather than on the digest,
so the digest is advisory.

Every definition and every role-permission relationship links to one or more sources through
explicit link tables — one per definition kind (category, permission, role, and role-permission).
Each link records whether the contribution was a base definition or an extension, and the
contributing file's priority so the winning metadata source is derivable. The common case is a
single link; the many-to-many exists to represent shared ownership and to make removal precise.

All sources are treated equally. ``openedx-authz`` is a schema provider like any other module, so
there is no core-versus-module flag; every definition originates from some module, including those
that ship with ``openedx-authz`` itself. Callers that care about a particular origin compare the
distribution name directly.

Data model
----------

The relationships between the entities are shown below. Four definition entities hold the compiled
schema; a single source entity records each distinct contribution; and one link entity per
definition kind attributes definitions to sources, each carrying the origin (base or extension) and
priority of the contribution.

.. code-block:: text

    Permission Category ─┐
        │                │ (base/extension, priority)
        │ groups         └──────────────┐
        ▼                               │
    Permission Definition ──────────────┤
        │                               │
        │ related by a                  │      ┌──────────────┐
        │ Role-Permission grant         ├─────►│    Source    │
        ▼                               │      │ (distribution,│
    Role Definition ────────────────────┤      │    module)   │
        │                               │      └──────────────┘
        │ has grants                    │
        ▼                               │
    Role-Permission grant ──────────────┘
        (role, permission, scope)
         → one rendered Casbin ``p`` row

    Each definition kind links to one or more Sources through its own link entity;
    every link carries the contribution's origin (base or extension) and priority.

Each entity's purpose:

.. list-table::
   :header-rows: 1
   :widths: 28 72

   * - Entity
     - Purpose
   * - Permission category
     - Display/grouping category for permissions. Grants no access; carries display metadata only.
   * - Permission definition
     - A compiled permission, identified by its namespace and name, with display metadata, its
       category, and supported scopes.
   * - Role definition
     - A compiled role, identified by a stable role id, with display metadata, supported scopes, and
       the ``hidden`` flag from `ADR 0023`_.
   * - Role-permission grant
     - One ``(role, permission, scope)`` grant. Corresponds one-to-one with a rendered Casbin ``p``
       row and is the atomic unit of attribution.
   * - Source
     - A distinct contribution, identified by ``(distribution, module)``. Resource path and content
       digest are advisory, non-identifying attributes.
   * - Definition-source links
     - One link entity per definition kind (category, permission, role, and role-permission),
       joining each definition to its contributing sources. Each link records the origin (base or
       extension) and priority, so the winning metadata source is derivable and shared ownership is
       representable.

3. Extending a role keeps both origins distinct
===============================================

Because attribution lives at the role-permission grain, the grant that first defined a role and a
later grant added by another module remain individually attributed. For ``course_admin``, assuming
``openedx-authz`` defines it and its base permissions:

* the role definition links to the module that defines it, as a base contribution;
* each base permission links to that same module as a base contribution; and
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

YAML schema files will always be the source of truth, display names and descriptions in the database
will always follow what the schema defines. This means that any translation strings derived from the
YAML files will match the text that the API will query, so the API can use those for applying
translations. The details on this mechanism is out of scope for this ADR.

5. Metadata changes update definitions in place
================================================

When a source file changes a display name, description, icon, or similar field, the next
deployment recompiles and updates the existing definition row, keyed by its stable identifier. No
new definition row is created and relationships and assignments are unaffected.

6. Adopt pre-existing policy rows; leave unmanaged rows untouched
=================================================================

On deployment, when policies are loaded, existing Casbin ``p`` rows are adopted rather
than duplicated: for each rendered ``(role, permission, scope)`` that already exists as a policy
row without a definition record, the loader creates the definition and relationship rows and links
them to the contributing source. A pre-existing policy row that no schema declares is left in place
and enforceable, but is not attributed and does not appear in the definition tables. Pruning such
unmanaged rows is out of scope.

Consequences
************

* Compiled definitions, including display metadata that previously had no home, are persisted and
  readable through the API.
* The origin of any role, permission, or individual role-permission grant is queryable, and the
  contributions of different modules to the same role remain distinguishable.
* Moving a definition between files in the same module does not change its recorded source.
* Removing an application becomes tractable: relationships and definitions whose only source is the
  removed application can be pruned, while shared ones remain. Removal itself remains out of scope
  and follows the assignment-safety rules of `ADR 0018`_.
* The existing ``ExtendedCasbinRule`` model is not reused, for the reasons given in the Context: it
  is one-to-one with its ``CasbinRule`` and geared toward assignments, whereas a definition may
  have multiple sources. It continues to describe role assignments (``g`` rows), while the new
  tables own definitions and provenance, keeping the two concerns separated.
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

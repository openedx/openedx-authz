0035: Persist Custom Roles in the Authorization Definition Tables
#################################################################

Status
******

**Draft**

Context
*******

Administrators need roles that match their organization, beyond the roles that ship with the
platform. Administrators create, copy, edit, and remove these custom roles from the
Administrative Console. A custom role has a name, a description, one resource type (courses or
libraries), and a set of existing permissions. Roles that ship with the platform stay read-only and
are customized by copying them.

Custom roles are the dynamic roles of `ADR 0016`_, which requires the authz model to store their
definitions. `ADR 0018`_ requires static and custom roles to share one set of role IDs and the
schema loader to preserve custom roles, but does not say where custom roles are stored.

`ADR 0025`_ added tables for compiled static definitions: categories, permissions, roles, and
role-permission grants, each linked to the module that contributed it. The role catalog
(`ADR 0028`_) reads roles from these tables and already reserves a ``definition_kind`` field with the
values ``static`` and ``user_defined``. Today, a schema deployment deletes every role and grant in
these tables that the compiled schema does not declare, so it would delete custom roles.

Decision
********

1. Store custom roles in the definition tables
==============================================

A custom role is a row in the role-definition table, and each permission it grants is a row in the
role-permission table, the same as for a static role. The role row records its definition kind,
``static`` or ``user_defined``, matching `ADR 0028`_. The kind never changes after creation.

A custom role has no source links, because no module contributed it, unlike the static definitions
that `ADR 0025`_ attributes to a source. Its grants need no separate kind flag: static roles cannot
be edited through the API, so a grant is user-defined exactly when the role that owns it is.

Custom roles only reference existing permissions. They do not create permissions or categories,
which stay static.

Custom roles are never hidden: their ``hidden`` flag is always false. Hiding a role (`ADR 0023`_) is
a schema extension that applies to static roles when the schema loads. A custom role that is no
longer needed is removed instead (section 4).

2. Identity and display fields
==============================

Custom roles are global to the instance. Their IDs use the reserved prefix ``custom_`` followed by
the display name converted to the role ID format (``[a-z][a-z0-9_]*``). The ID is set at creation and
never changes, so renaming a role does not affect its assignments or policy rows.

The name is converted with the Python standard library, so no transliteration dependency is needed:

#. Normalize the name to Unicode NFKD, which separates accents from their letters, and drop the
   characters that are still not ASCII.
#. Lowercase it, and replace each run of characters other than letters and digits with one
   underscore.
#. Trim underscores from both ends.

For example:

* "Course Designer" becomes ``custom_course_designer``.
* "Diseñador de cursos" becomes ``custom_disenador_de_cursos``.
* If that ID is taken, including by a removed role (section 4), the next one is
  ``custom_course_designer_2``.
* A name with nothing left after conversion, such as one written only in a non-Latin script,
  becomes ``custom_role``.

A custom role ID is at most 64 characters. The converted name is cut before the numeric suffix is
added, and underscores left at the end of the cut are trimmed. The role ID column allows 255
characters, but each assignment is also stored under a 255-character key that joins the subject,
role, and scope keys, so a short role ID leaves room for long scope keys. The display name keeps the
255-character limit of its column.

Schema validation rejects static role IDs that start with ``custom_``, so the two kinds of role
cannot collide. The prefix also identifies custom roles in Casbin rows and logs.

The display name and description are stored as entered and are not translated (`ADR 0020`_). The
role's ``scopes`` stays a list, but the API accepts one resource type for now, so supporting several
later needs no data migration.

Role identifier conflicts (amends ADR 0018 section 4)
-----------------------------------------------------

`ADR 0018`_ section 4 handles static and custom role name collisions at runtime and leaves custom
role naming out of scope. The dynamic role API rejects a name used by a static role, and a
deployment stops when a new static role conflicts with an existing custom role. This ADR sets the
naming rule that section 4 left open, so it replaces that runtime handling:

* A static role can never collide with a custom role, because static IDs cannot start with
  ``custom_`` and custom IDs always do. A deployment no longer stops because of a static and
  custom role name conflict, and the custom role API no longer needs to check names against static
  roles.
* A static role ID that starts with ``custom_`` is now a schema validation error, reported before
  any database change, with the contributing package. This is where a package that already ships
  such an ID is caught.
* Uniqueness among custom roles remains a runtime concern, handled by the numeric suffix
  (``custom_course_designer_2``).

The rest of `ADR 0018`_ section 4 still applies: static and custom roles share one set of role IDs.
`ADR 0018`_ carries a matching addendum.

3. Changes apply to the definition and the policy together
==========================================================

Creating, editing, or removing a custom role updates its definition rows and its Casbin ``p`` rows
in one transaction, then invalidates the policy cache, as `ADR 0018`_ requires for deployments.
These writes use the same lock as schema apply. Changes apply right away to every user who holds the
role.

Copying a role is not a separate operation. The Administrative Console reads an existing role from
the catalog and sends its resource type and permissions, which the administrator can change, in a
normal create request. The catalog lists only roles that are not hidden, so only those
can be copied. The new role gets no assignments and keeps no link to the original.

4. Removing a custom role
=========================

Removing a custom role keeps its role-definition row and marks it as removed, with the time of
removal. Its grants, its Casbin ``p`` rows, and its assignments are deleted in the same transaction.
A removed role is left out of the catalog, cannot be assigned or edited, and grants no access.

The role ID stays reserved, so creating "Course Designer" again gives ``custom_course_designer_2``.
Audit records (`ADR 0012`_) store role keys as plain strings. If a new role could take a removed
role's ID, its history would mix with the old role's records. Keeping the row also lets those
records show the removed role's display name.

When a custom role has assignments, the request to remove it must state explicitly that the
assignments are deleted with the role, or it is rejected. A role with no assignments needs no such
statement. Each deleted assignment is recorded the same way assignment removals are recorded today.

5. Schema deployments
=====================

The schema loader does not create, update, or remove custom roles. When a deployment removes a
permission that a custom role grants, it stops before any write and
reports each affected grant, so Casbin keeps the last applied policy (`ADR 0018`_).

An explicit option, separate from the force option for removing roles, lets the operator drop
those grants and their ``p`` rows in the same deployment. A release that removes a permission must
say so in its operator release notes and name this option. A custom role left with no permissions
remains, so its assignments are kept.

Consequences
************

* The catalog, the assignment flow, and enforcement read static and custom roles from the same
  tables.
* The schema loader's prune step must skip custom roles and their grants. It drops a custom role's
  grant only when the schema removed the permission and the operator passed the option from
  section 5.
* A deployment cannot narrow a custom role unless the operator opts in, and releases that remove
  permissions must document the option in their operator release notes.
* Removing a custom role cannot leave orphaned assignments.
* Removed custom roles stay in the role-definition table, so their IDs are never reused and audit
  records can still name them. Queries for active roles must exclude them.
* Schema validation and the :ref:`Authorization Schema Reference` must reserve the ``custom_``
  prefix.
* Custom roles have no source attribution.
* Static and custom role name conflicts are prevented by the ``custom_`` prefix rule instead of
  detected at deployment, which supersedes the runtime conflict handling in `ADR 0018`_ section 4.

This ADR does not decide who can manage custom roles, the REST API contract, or how dependent
permissions are added. Future ADRs decide these. It also does not cover a change history for role
definitions or roles with several resource types.

Rejected Alternatives
*********************

Separate tables for custom roles
================================

Every catalog query would have to merge two tables, the code that writes ``p`` rows would exist
twice, and the shared role ID rule from `ADR 0018`_ would have to be checked across both tables.

Infer custom roles from missing source links
============================================

A role with no source links could also be a leftover or the result of an incomplete write. An
explicit definition kind avoids the guesswork and is the value the catalog already returns.

References
**********

* `ADR 0012`_
* `ADR 0016`_
* `ADR 0018`_
* `ADR 0020`_
* `ADR 0023`_
* `ADR 0025`_
* `ADR 0028`_
* `Issue #467`_

.. _ADR 0012: 0012-auditability.rst
.. _ADR 0016: 0016-static-and-dynamic-roles.rst
.. _ADR 0018: 0018-authorization-schema-lifecycle.rst
.. _ADR 0020: 0020-authorization-schema-internationalization.rst
.. _ADR 0023: 0023-extend-static-roles.rst
.. _ADR 0025: 0025-authorization-schema-source-tracking.rst
.. _ADR 0028: 0028-api-contract-for-role-catalog.rst
.. _Issue #467: https://github.com/openedx/openedx-authz/issues/467

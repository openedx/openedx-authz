0034: Define Permission Dependencies in the Authorization Schema
################################################################

Status
******

**Draft**

Context
*******

Before `PR #538`_, ``authz.policy`` declared permission dependencies as Casbin ``g2`` rows. For example, ``g2, act^content_libraries.edit_library_content, act^content_libraries.view_library`` meant that editing library content requires viewing the library. That PR moved static roles and permissions into the authorization schema (`ADR 0017`_) and removed the policy file, but the schema had no field for dependencies, so new installations no longer load them.

The Custom Roles feature needs these dependencies for two reasons:

* When an administrator enables a permission, the UI also selects every permission it depends on. When an administrator disables a permission that other selected permissions depend on, the UI warns first and then also disables those permissions.
* The ``g2`` rows must be generated from the schema rather than from a policy file.

`ADR 0022`_ deferred permission implication and listed what a later schema version must define before adding it. This ADR adds permission dependencies and covers those points.

Decision
********

1. Syntax
=========

A permission may declare an optional ``depends_on`` list with the complete IDs of the permissions it directly requires. A dependency means that granting the permission also grants the permissions it depends on. For example, granting ``edit_library_content`` also grants ``view_library``, because a user cannot edit the content of a library they cannot view.

.. code-block:: yaml

   permissions:
     - namespace: content_libraries
       name: edit_library_content
       display_name: Edit
       # ...
       scopes:
         - lib
       depends_on:
         - content_libraries.view_library

Only the file that defines a permission declares its dependencies. Role extensions cannot add or remove dependencies.

2. Schema version
=================

``depends_on`` is allowed only in files that declare ``schema_version: "1.1"``. The field stays optional in ``1.1``, so a ``1.1`` file that declares no ``depends_on`` is valid and means the same as it would in ``1.0``. Files that declare ``"1.0"`` keep their current meaning, and a ``1.0`` file that declares ``depends_on`` is rejected as an unknown field.

``1.0`` and ``1.1`` files are a supported combination. The "unsupported combinations of schema versions" check in `ADR 0017`_ does not reject a deployment that loads both, so a file can move to ``1.1`` without requiring every other file to move with it. For example, ``library_permissions.yaml`` can declare ``1.1`` and ``depends_on``, while ``library_roles.yaml`` stays at ``1.0``.

Version ``1.1`` has its own JSON Schema file, ``authz-schema-v1.1.json``, next to the existing ``authz-schema-v1.json``. The existing file keeps ``"const": "1.0"`` and does not change, so tools that validate ``1.0`` files continue to work. The ``1.1`` file accepts everything ``1.0`` accepts and adds the optional ``depends_on`` field. The validator selects the JSON Schema file from the ``schema_version`` that each file declares.

3. Validation
=============

Validation rejects:

* a dependency on a permission that is not defined;
* a permission that depends on itself, or a dependency cycle;
* a dependency whose scope namespaces do not include every scope namespace of the dependent permission; and
* a role whose resolved permissions, after role extensions are applied, include a permission but not all of its direct and indirect dependencies.

The last rule means a role always lists every permission it grants, and a ``remove_permissions`` extension cannot remove a dependency that another permission on the role still needs. It applies to roles and role extensions in every file, regardless of the ``schema_version`` the file declares.

4. Casbin representation
========================

The renderer creates one ``g2`` row for each direct dependency:

.. code-block:: text

   g2, act^content_libraries.edit_library_content, act^content_libraries.view_library

The renderer owns these rows and adds, adopts, and removes them the same way it handles ``p`` rows (`ADR 0018`_, `ADR 0025`_). ``model.conf`` and its matcher do not change.

For schema roles, the validation in section 3 already makes ``g2`` rows redundant, because every role lists its dependencies. The rows are still rendered because:

* Roles that do not pass through schema validation, such as roles stored only in the database and ``p`` rows that no schema declares, can still be missing a dependency. The ``g2`` row grants the dependency, so a permission on such a role still works.
* The matcher already checks ``g2``, and existing installations already store these rows, so authorization decisions stay the same as before `PR #538`_.
* The dependencies stay in the Casbin policy, where tools that read the policy, such as the ``enforcement`` management command, can see them.

5. Definition storage
=====================

The loader stores each direct dependency as one row that links a permission definition to the permission it depends on, next to the definition tables from `ADR 0025`_. Each row corresponds to one rendered ``g2`` row, in the same way each stored role-permission grant corresponds to one ``p`` row. The row has no scope, because ``g2`` rows have none.

Dependencies do not have their own source records. Only the file that defines a permission declares its dependencies, so a dependency's source is the permission's source. Two files that define the same permission with different dependencies are a base-definition conflict, which validation rejects (`ADR 0031`_).

The renderer uses these rows to decide which ``g2`` rows it owns:

* A stored ``g2`` row that matches a rendered one, such as a row loaded from ``authz.policy`` before `PR #538`_, is adopted without being rewritten.
* A stored ``g2`` row that no schema declares stays in place and unattributed, like unmanaged ``p`` rows.
* When a dependency leaves the schema, or its permission is removed, the renderer removes the dependency row and its ``g2`` row in the same transaction.

6. API
======

The role catalog (`ADR 0028`_) returns each permission's direct ``depends_on`` list. Clients compute indirect dependencies when they need them. Because of the role rule in section 3, a role's listed permissions are the same as the permissions it grants, so the API does not need to separate direct and implied permissions.

7. UI behavior
==============

The UI uses ``depends_on`` in both directions when an administrator edits the permissions of a custom role:

* When the administrator selects a permission, the UI also selects every permission it depends on, directly or indirectly.
* When the administrator deselects a permission that other selected permissions depend on, the UI warns the administrator before deselecting it. The warning lists the permissions that will also be deselected. If the administrator confirms, the UI deselects the permission and every selected permission that depends on it, directly or indirectly. If the administrator cancels, nothing changes.

The UI computes the permissions that depend on a given permission by reversing the ``depends_on`` lists it received from the role catalog (section 6). The role rule in section 3 stays the authoritative check, so a request that leaves a permission selected without its dependencies is rejected by the Custom Roles API regardless of what the UI does.


Consequences
************

* New installations load library ``g2`` rows again.
* Schema authors declare dependencies once, on the permission they belong to.
* A schema that adds a permission to a role without its dependencies fails validation, including a ``1.0`` file that lists a permission to which a ``1.1`` file has added ``depends_on``.
* ``1.0`` files, and ``1.1`` files that do not use ``depends_on``, keep their current meaning, and ``1.0`` and ``1.1`` files can be loaded together.
* The repository ships a second JSON Schema file for ``1.1``, which must be kept in sync with ``authz-schema-v1.json`` for the fields they share.
* Tests check the validation rules and confirm that enforcement results match the explicit role permissions.
* The Custom Roles API should apply the same role rule to roles that users create.

Rejected Alternatives
*********************

Top-level ``permission_dependencies`` section
=============================================

A separate section would let any file add dependencies to a permission it does not own, which would require the override rules that `ADR 0031`_ avoids for base definitions.

Dependencies as display metadata only
=====================================

The UI would select dependencies, but Casbin would have no ``g2`` rows. The schema would then not be the full source for the Casbin policy.

Role inheritance
================

Inheritance links roles, not permissions. It does not tell the UI which permissions to select together.

References
**********

* `ADR 0017`_
* `ADR 0018`_
* `ADR 0022`_
* `ADR 0025`_
* `ADR 0028`_
* `ADR 0031`_
* `Issue #91`_
* `Issue #523`_
* `PR #538`_
* `Casbin RBAC documentation`_

.. _ADR 0017: 0017-static-authorization-schema.rst
.. _ADR 0018: 0018-authorization-schema-lifecycle.rst
.. _ADR 0022: 0022-defer-authorization-implications.rst
.. _ADR 0025: 0025-authorization-schema-source-tracking.rst
.. _ADR 0028: 0028-api-contract-for-role-catalog.rst
.. _ADR 0031: 0031-priority-applies-to-role-extensions-only.rst
.. _Issue #91: https://github.com/openedx/openedx-authz/issues/91
.. _Issue #523: https://github.com/openedx/openedx-authz/issues/523
.. _PR #538: https://github.com/openedx/openedx-authz/pull/538
.. _Casbin RBAC documentation: https://casbin.apache.org/docs/rbac#named-role-systems-and-permission-dependencies

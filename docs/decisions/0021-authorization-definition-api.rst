0021: Expose Authorization Definitions Through APIs
####################################################

Status
******

**Draft**

Context
*******

``GET /api/authz/v1/roles/?scope=<scope>`` already derives role and permission IDs from the loaded Casbin policy and returns the number of assigned users. However, it does not include the display names, descriptions, categories, icons, or source information defined in the authz schema, nor does it distinguish static roles from user-defined roles. The client applications must keep their own copy of the missing fields, which means that a role contributed by an application still requires frontend changes even when Casbin can already assign and enforce it.

Decision
********

1. Stored definitions
=====================

The AuthZ API reads static and user-defined roles from the authz model, where both kinds are stored after deployment. It returns roles, permissions, and categories in the format clients need, without exposing the Casbin rows used for permission checks.

2. Extend the roles endpoint
============================

Role listing and assignment screens continue to use the existing scope-based roles endpoint, with each role gaining:

* the stable role identifier;
* localized display name and description;
* supported scope namespaces;
* complete permission identifiers;
* whether the role is ``static`` or ``user_defined``.

The response keeps ``user_count`` alongside the new fields, so existing clients that read only ``role``, ``permissions``, and ``user_count`` remain compatible.

Because a static role is owned by its schema, clients cannot edit or delete it through the user-defined role API.

3. Permission and category definitions
======================================

The API also provides the information needed to display permissions and categories, including:

* the schema version used by the static definitions;
* permissions with the complete stable ID, separate ``namespace`` and ``name`` fields, translated display fields, categories, supported scopes, and optional icons; and
* normalized permission categories with translated display fields.

4. Source information
=====================

Responses may identify a role as ``static`` or ``user_defined`` so clients can tell where it came from. Whether the API should expose more detailed source information, such as the application and schema path behind a static role, remains an open question.

The standard roles endpoint may return the following object.

.. code-block:: json

   {
     "role": "course_observer",
     "display_name": "Course observer",
     "permissions": ["courses.view_course"],
     "definition_kind": "static",
     "user_count": 3
   }

The exact field name and whether it belongs in the default response remain open API-contract decisions.

5. Role assignment and localization
===================================

Assignment and validation endpoints read the roles available for the requested scope from the authz model instead of a static Python list. When returning those roles, the API translates static display fields into the requested language but keeps role and permission IDs unchanged.

Consequences
************

* Frontend clients can render roles and permissions contributed by applications without its own definition arrays.
* Existing clients keep using the current endpoint and response fields.
* Responses containing translated display fields need locale-aware caching.

Rejected Alternatives
*********************

Return raw Casbin policy rows
=============================

They expose engine-specific namespaces and omit the display fields clients need.

Keep role and permission metadata in the frontend
=================================================

Applications would still require frontend releases, and the frontend definitions could drift from the policy enforced by Casbin.

Replace the existing roles endpoint
===================================

The current endpoint already serves scope-based role discovery and assignment screens. Extending it preserves the established entry point and response fields.

References
**********

* `ADR 0016`_
* `ADR 0020`_

.. _ADR 0016: 0016-static-and-dynamic-roles.rst
.. _ADR 0020: 0020-authorization-schema-internationalization.rst

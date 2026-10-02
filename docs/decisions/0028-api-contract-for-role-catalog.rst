0028: API Contract for the Role and Permission Catalog
######################################################

Status
******

**Draft**

Context
*******

`ADR 0021`_ decided that ``GET /api/authz/v1/roles/`` must return the authorization
definitions stored in the authz model (display names, descriptions, categories, icons and
definition kind) so clients no longer keep their own copy of them. It left the exact
response shape open.

The Roles and Permissions tab of the Admin Console (`frontend-app-admin-console`_)
renders a matrix for one scope type at a time (Courses or Libraries):

* the columns are the roles, each with a name and a description;
* the rows are permissions grouped by category; a category has an icon, a label and a
  description shown in a tooltip, and a permission has an icon and a label;
* each cell says whether the role grants the permission.

Today the frontend hardcodes all of this (``course/constants.ts`` and
``library/constants.ts``) and builds the matrix in ``buildPermissionMatrixByResource``.
The matrix needs every permission of the scope type, including the ones a role does not
grant, so a list of roles that only carries the permissions each one grants is not
enough. This ADR defines a response that lets the client build the matrix directly.

Decision
********

Extend the existing ``GET /api/authz/v1/roles/`` endpoint, served by ``RoleListView``, to
return a catalog for a scope type. A single call returns the categories, the permissions
and the roles that exist for the scope type, without any knowledge hardcoded in the client.
No new endpoints are added.

Query by scope type
===================

The endpoint is queried by ``scope_type`` instead of ``scope``, like ``ScopesAPIView``
(``GET /api/authz/v1/scopes/``) and with the same accepted values, ``course`` and
``library`` (``ScopesTypeField``). The catalog describes what a scope type offers, not a
particular course or library, so a concrete scope is not needed.

* ``scope_type`` is required. Unlike ``/scopes/``, a request without it is invalid (400)
  because one matrix cannot mix course and library roles.
* The scope type is mapped to its scope namespace (``course`` to ``course-v1``, ``library``
  to ``lib``).
* The ``scope`` query parameter is removed. The Admin Console does not call
  ``GET /api/authz/v1/roles/`` (it only uses ``/roles/users/``), so no released client
  depends on the old shape.

Authorization
=============

The permission needed depends on the requested ``scope_type``, so a user cannot read the
roles of a scope type whose team they cannot view:

* ``scope_type=course`` requires ``courses.view_course_team`` (``COURSES_VIEW_COURSE_TEAM``).
* ``scope_type=library`` requires ``content_libraries.view_library_team``
  (``VIEW_LIBRARY_TEAM``).

The check is not tied to one scope, so the user must hold the permission in at least one
scope of any kind (a specific course or library, or an org or platform glob), as
``AnyScopePermission`` does. Superusers and staff always pass.

The existing classes cannot express this. ``DynamicScopePermission`` needs a concrete
``scope`` in the request, which no longer exists. ``AnyScopePermission`` accepts any of the
permissions declared by ``@authz_permissions``, which is how ``ScopesAPIView`` lets a user
with only the course permission also query libraries. The implementation therefore adds a
permission class that, like ``AnyScopePermission``, looks for the permission in any scope
with ``get_scopes_for_user_and_permission``, but it reads ``scope_type`` from the request
and only requires the permission mapped to that type. An invalid or missing ``scope_type``
is rejected as a 400 by the serializer, not by the permission class.

Extensibility to new scope types (future work)
==============================================

For now the two supported scope types, ``course`` and ``library``, and their mapping to a
scope namespace and view-team permission stay explicit, as described above. This is kept in
one helper so it is not duplicated in the view.

A possible future improvement is to stop hardcoding the scope types. ``ScopeMeta`` already
registers every ``ScopeData`` subclass in ``scope_registry``, keyed by its ``NAMESPACE``
(``course-v1``, ``lib``), so the endpoint could resolve the requested scope type from that
registry. Any plugin that registers a scope class would then contribute a new scope type
without changing authz:

* The accepted ``scope_type`` values and their namespace would come from ``scope_registry``
  instead of a fixed enum.
* The catalog would not change in shape. It is built from the authz schemas, so a new scope
  type appears as soon as a schema declares permissions and roles for its namespace.
* The permission required to read the catalog would be declared by the scope class. A scope
  type that does not declare one would be rejected rather than left open.

Open point for that work: ``/scopes/`` exposes the short names ``course`` and ``library``
(``ScopesTypeField``), not the namespaces, so using ``NAMESPACE`` as the key would need an
alias or a change in the accepted values.

Role user count
===============

``user_count`` is kept, but it is no longer calculated for a specific scope. It is now
calculated by scope type: the number of users assigned to the role in the requested scope
type.

Data source
===========

The endpoint reads from the authz schema models (``AuthzRoleDefinition``,
``AuthzRolePermission``, ``AuthzPermissionDefinition`` and ``AuthzPermissionCategory``),
the same data the Casbin policy is rendered from. It does not keep a parallel copy and does
not return raw Casbin rows.

* ``permissions`` contains the permissions whose supported scopes include the namespace.
* ``roles`` contains the non-``hidden`` roles (`ADR 0023`_) with at least one grant in the
  namespace. Each role's ``permissions`` lists the identifiers of the grants in that
  namespace.
* ``categories`` contains only the categories used by those permissions. Categories are
  global and a schema may define one without permissions, or only with permissions of
  another scope type, so the rest are left out.
* Categories, permissions and roles are returned in a stable order (by identifier).
  Explicit display ordering is a follow-up.

One normalized shape
====================

Permission metadata is sent once in the top-level ``permissions`` list, and a role only
references permissions by identifier. This avoids repeating the metadata of a permission
for every role that grants it, and it contains the permissions a role does not grant, which
the matrix requires. To build a cell, the client checks whether the row's permission ``id``
is in the role's ``permissions``.

Every permission has a ``category`` with the id of one category. The authz schema requires
it, so it is never ``null``. A category that no permission of the requested scope type uses
is not returned, even if it exists in the schema.

Definition kind
===============

Every role includes ``definition_kind``, with one of the values ``static`` or
``user_defined``. Only static roles are stored today, so the value is always ``static``
until user-defined roles exist. The field is reserved now so clients do not need to change
later. Detailed source information (distribution, module, schema path, see `ADR 0025`_) is
not exposed.

Localization
============

``display_name`` and ``description`` of roles, permissions and categories are returned in
the language of the request, following `ADR 0020`_ and Django's normal fallback rules.
Identifiers (``role``, ``id``, ``namespace``, ``name``) and ``icon`` names are never
translated. Since the body depends on the request language, the response must vary on
``Accept-Language``.

Icons are Paragon icon names (validated by the schema, see `ADR 0026`_). The client maps
the name to its component; the API only returns the name, or ``null``.

Pagination
==========

The endpoint stays paginated with the existing ``AuthZAPIViewPagination`` and the ``page``
and ``page_size`` parameters. The pagination applies to the roles, which are the
``results``. The ``categories`` and ``permissions`` catalogs are not paginated: they are
bounded by what the schemas of one scope type declare, and every page carries the complete
catalogs so any page can be rendered on its own. A client that needs the whole matrix in one
request asks for a ``page_size`` large enough to hold every role.

REST API
========

GET /api/authz/v1/roles/
------------------------

Retrieve the roles, permissions and categories available for a scope type.

Query Parameters:
^^^^^^^^^^^^^^^^^

-  ``scope_type`` (required): Scope type to query. Either ``course`` or ``library``.
-  ``page`` (optional): Page number for pagination of the roles.
-  ``page_size`` (optional): Number of roles per page.

Example:

.. code::

   GET /api/authz/v1/roles/?scope_type=course

Response Body:
^^^^^^^^^^^^^^

.. code:: ts

   {
       count: number
       next: string | null
       previous: string | null
       scope_type: "course" | "library"
       categories: Array<{
           id: string
           display_name: string
           description: string
           icon: string | null
       }>
       permissions: Array<{
           id: string              // complete id, e.g. "courses.view_course"
           namespace: string
           name: string
           display_name: string
           description: string
           icon: string | null
           category: string        // id of an entry of "categories"
       }>
       results: Array<{        // roles, paginated
           role: string
           display_name: string
           description: string
           icon: string | null
           definition_kind: "static" | "user_defined"
           permissions: string[]   // ids of entries of "permissions"
           user_count: number
       }>
   }

Example:

.. code:: json

   {
       "count": 2,
       "next": null,
       "previous": null,
       "scope_type": "course",
       "categories": [
           {
               "id": "course_access_content",
               "display_name": "Course access & content",
               "description": "Open the course and work with its content.",
               "icon": "BookOpen"
           }
       ],
       "permissions": [
           {
               "id": "courses.view_course",
               "namespace": "courses",
               "name": "view_course",
               "display_name": "View course",
               "description": "View the course and its content in Studio.",
               "icon": "RemoveRedEye",
               "category": "course_access_content"
           },
           {
               "id": "courses.create_course",
               "namespace": "courses",
               "name": "create_course",
               "display_name": "Create course",
               "description": "Create new courses.",
               "icon": "Plus",
               "category": "course_access_content"
           }
       ],
       "results": [
           {
               "role": "course_staff",
               "display_name": "Course Staff",
               "description": "Can edit and publish course content.",
               "icon": null,
               "definition_kind": "static",
               "permissions": ["courses.view_course"],
               "user_count": 8
           },
           {
               "role": "course_auditor",
               "display_name": "Course Auditor",
               "description": "Can view the course.",
               "icon": null,
               "definition_kind": "static",
               "permissions": ["courses.view_course"],
               "user_count": 3
           }
       ]
   }

Possible response codes:
^^^^^^^^^^^^^^^^^^^^^^^^

-  200: Ok, includes the Response Body defined above.
-  400: Bad Request, ``scope_type`` is missing or not one of the supported values.
-  401: Unauthorized, the user is not authenticated.
-  403: Forbidden, the user lacks ``courses.view_course_team`` (``scope_type=course``) or
   ``content_libraries.view_library_team`` (``scope_type=library``) in any scope.

Consequences
************

* The Roles and Permissions tab can render its matrix from one request and drop
  ``course/constants.ts`` and ``library/constants.ts``. Roles and permissions contributed by
  other applications show up without a frontend release.
* This is a breaking change to ``GET /api/authz/v1/roles/``: ``scope`` becomes
  ``scope_type``, ``user_count`` now counts across the scope type instead of one scope, and
  the response adds the ``categories`` and ``permissions`` catalogs next to the paginated
  roles. It is low risk because no released client calls the endpoint. Tests
  and docs that reference the old shape must be updated, and the deviation from the
  compatibility promise of `ADR 0021`_ is intentional.
* Implementations must load definitions with a constant number of queries, not one query
  per role or permission.
* Every page repeats the ``categories`` and ``permissions`` catalogs, which is a small
  cost for a pageable roles list.
* A new permission class is needed for the per-scope-type authorization.
* ``definition_kind`` is reserved for user-defined roles. Their storage, the translation of
  their names and any source detail remain out of scope.
* A role present in the Casbin policy but with no stored definition cannot be described. It
  is returned with its identifier as ``display_name`` and empty metadata instead of being
  omitted, so enforcement and listing stay consistent.

Rejected Alternatives
*********************

Separate permission and category endpoints
==========================================

The Admin Console would need several requests and would have to join the data itself.

References
**********

* `ADR 0020`_
* `ADR 0021`_
* `ADR 0023`_
* `ADR 0024`_
* `ADR 0025`_
* `ADR 0026`_

.. _frontend-app-admin-console: https://github.com/openedx/frontend-app-admin-console
.. _ADR 0020: 0020-authorization-schema-internationalization.rst
.. _ADR 0021: 0021-authorization-definition-api.rst
.. _ADR 0023: 0023-extend-static-roles.rst
.. _ADR 0024: 0024-api-contract-for-user-grouped-role-assignments.rst
.. _ADR 0025: 0025-authorization-schema-source-tracking.rst
.. _ADR 0026: 0026-paragon-icon-list-maintenance.rst

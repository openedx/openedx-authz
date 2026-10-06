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

The authz model is the source of truth for what roles and permissions exist, but the
descriptive information about them (display names, descriptions, categories and icons) is
not exposed by the API. Clients such as the Admin Console (`frontend-app-admin-console`_)
keep their own hardcoded copy of it (``course/constants.ts`` and ``library/constants.ts``)
and use it in several places: the Roles and Permissions matrix, the permissions sub-table
and the role list of the assignment wizard.

Clients need more than the permissions each role grants. They need:

* every role of a scope type, each with a name and a description;
* every permission of the scope type, including the ones a role does not grant, grouped by
  category; a category has an icon, a label and a description, and a permission has an
  icon and a label;
* which permissions each role grants.

This ADR makes the API the source of truth for the descriptive information of the authz
model. It defines a response that returns it together with the role-permission
relationships, so clients can build any view from it, whatever the way they choose to
present it, without keeping their own copy.

Decision
********

Extend the existing ``GET /api/authz/v1/roles/`` endpoint, served by ``RoleListView``, to
return a catalog for one or more scope types. A single call returns the categories, the
permissions and the roles that exist for the requested scope types, without any knowledge
hardcoded in the client. No new endpoints are added.

Query by scope type
===================

The endpoint is queried by ``scope_types`` instead of ``scope``. It is a comma-separated
list (for example ``?scope_types=course,library``) whose values are the ones accepted by
``ScopesAPIView`` (``GET /api/authz/v1/scopes/``) for ``scope_type``, ``course`` and
``library`` (``ScopesTypeField``). The catalog describes what scope types offer, not a
particular course or library, so a concrete scope is not needed.

A list is accepted, instead of a single ``scope_type``, so that listing the roles
dynamically for assignments can ask for several scope types at once when roles with
multiple scope types are supported. Such roles do not exist yet, so nothing specific to
them is implemented now.

* ``scope_types`` is required and must have at least one value. Unlike ``/scopes/``, a
  request without it is invalid (400). Empty and unknown values are also invalid (400).
* Each scope type is mapped to its scope namespace (``course`` to ``course-v1``, ``library``
  to ``lib``).
* A role is returned if it has grants in **any** of the requested scope types (OR).
* A client that presents the roles of one scope type at a time, like the Roles and
  Permissions tab, sends a single value.
* The query parameter keeps the short names (``course``, ``library``), but the response
  returns the requested scopes with the namespaces used by the backend (``course-v1``,
  ``lib``) in ``scopes``, see `Scopes in the response`_.
* The ``scope`` query parameter is removed. The Admin Console does not call
  ``GET /api/authz/v1/roles/`` (it only uses ``/roles/users/``), so no released client
  depends on the old shape.

Authorization
=============

The permission needed depends on the requested ``scope_types``, so a user cannot read the
roles of a scope type whose team they cannot view. The user must hold the permission of
**each** requested scope type:

* ``course`` requires ``courses.view_course_team`` (``COURSES_VIEW_COURSE_TEAM``).
* ``library`` requires ``content_libraries.view_library_team`` (``VIEW_LIBRARY_TEAM``).

The check is not tied to one scope, so for each requested scope type the user must hold its
permission in at least one scope of any kind (a specific course or library, or an org or
platform glob), as ``AnyScopePermission`` does. Superusers and staff always pass.

The existing classes cannot express this. ``DynamicScopePermission`` needs a concrete
``scope`` in the request, which no longer exists. ``AnyScopePermission`` accepts any of the
permissions declared by ``@authz_permissions``, which is how ``ScopesAPIView`` lets a user
with only the course permission also query libraries. The implementation therefore adds a
permission class that, like ``AnyScopePermission``, looks for the permission in any scope
with ``get_scopes_for_user_and_permission``, but it reads ``scope_types`` from the request
and requires the permission mapped to each requested type. An invalid or missing
``scope_types`` is rejected as a 400 by the serializer, not by the permission class.

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

* The accepted ``scope_types`` values and their namespace would come from ``scope_registry``
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
calculated by scope type: the number of users assigned to the role across the requested
scope types.

Data source
===========

The endpoint reads from the authz schema models (``AuthzRoleDefinition``,
``AuthzRolePermission``, ``AuthzPermissionDefinition`` and ``AuthzPermissionCategory``),
the same data the Casbin policy is rendered from. It does not keep a parallel copy and does
not return raw Casbin rows.

* ``permissions`` contains the permissions whose supported scopes include any of the
  requested namespaces (the union across the requested scope types). Each permission
  returns all its supported scopes in ``scopes``, not only the requested ones.
* ``roles`` contains the non-``hidden`` roles (`ADR 0023`_) with at least one grant in any
  of the requested namespaces. Each role's ``permissions`` lists the identifiers of the
  grants in those namespaces.
* ``categories`` contains only the categories used by those permissions. Categories are
  global and a schema may define one without permissions, or only with permissions of
  another scope type, so the rest are left out.
* Only roles with a stored definition are listed. A role that exists in the Casbin policy
  but has no stored definition is omitted, so the endpoint reads only from the database and
  filtering and pagination are done in a single query.
* Categories, permissions and roles are returned in a stable order (by identifier).
  Explicit display ordering is a follow-up.

Scopes in the response
======================

The top-level ``scopes`` field replaces ``scope_types``. It lists the scopes requested in
``scope_types``, in the format the backend uses: the scope namespace (``course-v1`` for
``course``, ``lib`` for ``library``).

Every permission also returns ``scopes``, the namespaces of the scopes it supports (for
example ``["course-v1"]``). It lists all the scopes the permission supports, even those not
requested, so a client can tell which scope types a permission applies to when it queries
several at once.

One normalized shape
====================

Permission metadata is sent once in the top-level ``permissions`` list, and a role only
references permissions by identifier. This avoids repeating the metadata of a permission
for every role that grants it, and it contains the permissions a role does not grant, which
clients need to show what a role lacks. To know whether a role grants a permission, the
client checks whether the permission ``id`` is in the role's ``permissions``.

Every permission has a ``category_id`` with the id of one category. The authz schema requires
it, so it is never ``null``. A category that no permission of the requested scope types uses
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
bounded by what the schemas of the requested scope types declare, and every page carries
the complete catalogs so any page can be rendered on its own. A client that needs every
role in one request asks for a ``page_size`` large enough to hold every role.

REST API
========

GET /api/authz/v1/roles/
------------------------

Retrieve the roles, permissions and categories available for one or more scope types.

Query Parameters:
^^^^^^^^^^^^^^^^^

-  ``scope_types`` (required): Comma-separated list of scope types to query, with at least
   one value. Each one is ``course`` or ``library``.
-  ``page`` (optional): Page number for pagination of the roles.
-  ``page_size`` (optional): Number of roles per page.

Example:

.. code::

   GET /api/authz/v1/roles/?scope_types=course

Response Body:
^^^^^^^^^^^^^^

.. code:: ts

   {
       count: number
       next: string | null
       previous: string | null
       scopes: Array<"course-v1" | "lib">   // requested scopes
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
           category_id: string     // id of an entry of "categories"
           scopes: Array<"course-v1" | "lib">   // all the scopes it supports
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
       "scopes": ["course-v1"],
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
               "category_id": "course_access_content",
               "scopes": ["course-v1"]
           },
           {
               "id": "courses.create_course",
               "namespace": "courses",
               "name": "create_course",
               "display_name": "Create course",
               "description": "Create new courses.",
               "icon": "Plus",
               "category_id": "course_access_content",
               "scopes": ["course-v1"]
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
-  400: Bad Request, ``scope_types`` is missing, has an empty value or has a value that is
   not supported.
-  401: Unauthorized, the user is not authenticated.
-  403: Forbidden, the user lacks ``courses.view_course_team`` (``course``) or
   ``content_libraries.view_library_team`` (``library``) in any scope, for any of the
   requested scope types.

Consequences
************

* Clients such as the Admin Console can build the Roles and Permissions tab, the permissions
  sub-table and the wizard role list from one request and drop ``course/constants.ts`` and
  ``library/constants.ts``. Roles and permissions contributed by other applications show up
  without a frontend release.
* This is a breaking change to ``GET /api/authz/v1/roles/``: the ``scope`` query parameter
  becomes ``scope_types``, the response returns the requested scopes in ``scopes`` (with
  backend namespaces such as ``course-v1`` and ``lib``), ``user_count`` now counts across
  the requested scope types instead of one scope, and the response adds the ``categories``
  and ``permissions`` catalogs (each permission with its ``scopes``) next to the paginated
  roles. It is low risk because no released client calls the endpoint. Tests
  and docs that reference the old shape must be updated, and the deviation from the
  compatibility promise of `ADR 0021`_ is intentional.
* Implementations must load definitions with a constant number of queries, not one query
  per role or permission.
* Every page repeats the ``categories`` and ``permissions`` catalogs, which is a small
  cost for a pageable roles list.
* A new permission class is needed for the per-scope-type authorization, which requires the
  permission of each requested scope type.
* ``definition_kind`` is reserved for user-defined roles. Their storage, the translation of
  their names and any source detail remain out of scope.
* A role present in the Casbin policy but with no stored definition is not listed, because
  it cannot be described. Listing it would require querying Casbin in addition to the
  database, which complicates filtering and pagination. Such a role still works for
  enforcement; it just does not appear in the catalog.

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

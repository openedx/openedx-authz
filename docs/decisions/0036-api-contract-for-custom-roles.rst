0036: API Contract for Custom Roles
###################################

Status
******

**Draft**

Context
*******

Custom roles are the dynamic roles of `ADR 0016`_. A custom role has a name, a description, one
resource type (courses or libraries), and a set of existing permissions. `ADR 0035`_ decides how
custom roles are stored, how their IDs are built, and what happens to assignments when a role is
copied or removed. It does not decide who can manage custom roles or the REST API.

The Administrative Console needs to create, read, edit, copy, and remove custom roles, and to move
a role's members to another role. Its Roles and Permissions table lists static and custom roles
together, with a member count and a last-updated date, and can be searched and sorted. Before
editing or removing a role, the console shows how many members the change affects. Copying a role
uses the create wizard: the administrator enters a name, picks a source role, and can change the
permissions copied from it before saving.

The role catalog (`ADR 0028`_) already lists custom roles next to static roles, distinguished by
``definition_kind``. The catalog returns each permission's dependencies (`ADR 0034`_), and
`ADR 0034`_ requires every role to list all the dependencies of the permissions it grants.

Decision
********

1. Authorization
================

Django staff and superusers can create, edit, copy, remove, or reassign the members of a role. Other
users are rejected with 403. This is the rule the other authorization endpoints already follow,
where staff and superusers bypass the scope checks. No new permission is added for these
operations.

Staff and superusers already pass every permission check, so a custom role cannot grant more access
than its creator has.

Reading the catalog keeps the rules of `ADR 0028`_. Giving a custom role to a user, or taking it
away, is not limited to staff and superusers. It uses the same endpoints and checks as static
roles: the user needs ``courses.manage_course_team`` or ``content_libraries.manage_library_team``
in the scope.

2. Endpoints
============

The endpoints extend ``/api/authz/v1/roles/`` and live in ``rest_api/v1/views.py``, as reusable
authorization endpoints (`ADR 0026`_).

.. list-table::
   :header-rows: 1

   * - Operation
     - Endpoint
   * - List, filter, search, and sort roles
     - ``GET /api/authz/v1/roles/`` (`ADR 0028`_)
   * - Create
     - ``POST /api/authz/v1/roles/``
   * - Read one role
     - ``GET /api/authz/v1/roles/<role>/``
   * - Edit name, description, or permissions
     - ``PATCH /api/authz/v1/roles/<role>/``
   * - Remove
     - ``DELETE /api/authz/v1/roles/<role>/``
   * - Move members to another role
     - ``POST /api/authz/v1/roles/<role>/reassign/``

3. Role fields
==============

Every role object, in the list and in the detail endpoint, adds two fields to the role of
`ADR 0028`_:

* ``user_count``: the number of distinct users with the role in any scope the caller can view. It
  is not the ``assignment_count`` of `ADR 0024`_, which counts the assignments of one user. A user
  with the role in three courses adds 3 to that user's ``assignment_count`` and 1 to the role's
  ``user_count``. The Members column and the member counts in the edit and remove warnings count
  users, so they use ``user_count``.
* ``updated_at``: when the name, description, or permissions of a custom role last changed.
  It is ``null`` for static roles. A permissions-only edit also updates the role row, so the
  date changes.

4. Filter, search, and sort
===========================

``definition_kind`` (``static`` or ``user_defined``, from `ADR 0028`_) is part of every role object.
The list adds it as a filter, so a client can ask for only the roles created by users. Without it,
the list returns both kinds.

The list also adds ``search`` (case-insensitive match on the display name), ``sort_by``
(``display_name``, ``scope_type``, ``user_count``, or ``updated_at``) and ``order`` (``asc`` or
``desc``), with the same names as `ADR 0024`_. The default is ``display_name`` ascending. Roles with
no ``updated_at`` sort last, and ties are broken by role ID.

Static role names are translated with gettext (`ADR 0020`_), so the database cannot search or sort
them in the user's language. The endpoint loads the roles of the requested scope types, filters,
searches, and sorts them in Python, and then paginates. The list is bounded by the schema roles plus
the custom roles of the instance. User counts are computed with one grouped query, not one query per
role.

5. Validation
=============

* A custom role has exactly one resource type, sent as a one-item ``scope_types`` list
  (``["course-v1"]`` or ``["lib"]``). The resource type cannot be changed after creation.
* A custom role grants at least one permission. Every permission must support the role's resource
  type.
* The display name is unique among all roles, static and custom, ignoring case. For static roles,
  the stored name is compared, not its translation. A taken name returns 409.
* The description is free text and may be empty. Both fields are stored as entered and are not
  translated (`ADR 0020`_).
* Static roles are read-only. Editing or removing one returns 400.

6. Copying
==========

Copying has no endpoint of its own. The client reads the source role's resource type and
permissions from the catalog, prefills the wizard with them, and sends a normal create request
with the name the administrator entered and the permissions they kept. The server does not know
the new role was copied, which matches `ADR 0035`_: the copy keeps no link to the original, and
assignments are not copied.

The name is always required, so the role ID derived from it (`ADR 0035`_) describes the role
instead of being generated from the source's name.

7. Permission dependencies
==========================

The server does not add dependencies. A request whose permissions leave out a dependency of another
permission in the set is rejected with 400, and the error lists the missing dependencies. This
covers both adding a permission without its dependencies and removing a dependency that another
permission still needs.

The client uses the ``depends_on`` lists in the catalog to select dependencies before it sends the
request, so the user sees the full set before saving.

8. Removing and reassigning
===========================

Removing a role that has assignments follows `ADR 0035`_. The request must choose what happens to
the assignments with the ``assignments`` query parameter:

* ``revoke`` deletes the assignments with the role.
* ``reassign`` moves them to ``target_role`` and then removes the role.

A request without ``assignments`` for a role that has assignments returns 409. A role with no
assignments is removed without it.

The reassign endpoint moves every assignment of a role to ``target_role`` at the same scope and
removes it from the source role, which is kept. The target must support the resource type of each
assignment's scope, and duplicates are merged, as `ADR 0035`_ decides. If any assignment cannot be
moved, nothing is moved.

9. Terminology
==============

Documentation and the UI call courses and libraries "resource types". The API keeps the
``scope_types`` field and the ``course-v1`` and ``lib`` values from `ADR 0028`_.

REST API
********

The role object is the one in the ``results`` of `ADR 0028`_, plus the fields of section 3:

.. code:: ts

   {
       // ...fields from ADR 0028, including:
       definition_kind: "static" | "user_defined"   // "user_defined" for every custom role
       user_count: number
       updated_at: string | null   // ISO 8601, null for static roles
   }

GET /api/authz/v1/roles/
========================

Adds the query parameters ``definition_kind``, ``search``, ``sort_by`` and ``order`` to
`ADR 0028`_. Unknown values of ``definition_kind``, ``sort_by`` or ``order`` return 400.

POST /api/authz/v1/roles/
=========================

.. code:: ts

   // Request
   {
       display_name: string
       description?: string
       scope_types: ["course-v1"] | ["lib"]
       permissions: string[]
   }

Returns 201 with the role object.

GET /api/authz/v1/roles/<role>/
===============================

Returns 200 with the role object.

PATCH /api/authz/v1/roles/<role>/
=================================

Accepts any of ``display_name``, ``description``, and ``permissions``. ``permissions`` replaces the
full list. Returns 200 with the role object.

DELETE /api/authz/v1/roles/<role>/
==================================

Query parameters: ``assignments`` (``revoke`` or ``reassign``) and ``target_role`` (required with
``reassign``). Returns 204.

POST /api/authz/v1/roles/<role>/reassign/
=========================================

.. code:: ts

   // Request
   { target_role: string }

   // Response
   { reassigned_count: number }

Response codes
==============

* 400: invalid request, missing dependencies, or a write to a static role.
* 401: the user is not authenticated.
* 403: the user is neither staff nor a superuser.
* 404: the role does not exist.
* 409: the display name is taken, or the role has assignments and ``assignments`` was not given.

Consequences
************

* The Administrative Console can manage custom roles without new permissions or a separate
  catalog.
* Users who are neither staff nor superusers cannot create roles, even if they manage a course
  team. Letting them do so later requires a decision on privilege escalation.
* Two roles cannot share a display name, so the assignment wizard and the Team Members view never
  show two roles with the same name.
* Clients must compute dependencies before saving. A client that does not gets a 400 that names the
  missing permissions.
* The role list brings back the ``user_count`` that `ADR 0028`_ removed, and searches, sorts, and
  paginates in Python instead of in one database query.
* Change history for custom roles is covered by a separate ADR.

Rejected Alternatives
*********************

Copy on the server
==================

A ``/duplicate/`` endpoint or a ``source_role`` field on create would add a second write path with
the same validation as create. The wizard lets the administrator change the copied permissions
before saving, so the client already sends the full definition.

Generate the name of a copy
===========================

A server-generated name such as "Course Staff (copy)" would also set the role ID, which never
changes (`ADR 0035`_). Roles copied this way would keep IDs that do not describe them after they
are renamed.

Server-side dependency closure
==============================

Adding dependencies silently would save permissions the user did not see, and it is unclear what to
do when a dependency is removed. Rejecting incomplete sets matches the rule `ADR 0034`_ applies to
schema roles.

Search and sort in the database
===============================

The database only has the untranslated names of static roles, so results would not match what the
user sees in other languages.

References
**********

* `ADR 0016`_
* `ADR 0020`_
* `ADR 0024`_
* `ADR 0026`_
* `ADR 0028`_
* `ADR 0034`_
* `ADR 0035`_
* `Issue #469`_

.. _ADR 0016: 0016-static-and-dynamic-roles.rst
.. _ADR 0020: 0020-authorization-schema-internationalization.rst
.. _ADR 0024: 0024-api-contract-for-user-grouped-role-assignments.rst
.. _ADR 0026: 0026-rest-api-domain-ownership-boundary.rst
.. _ADR 0028: 0028-api-contract-for-role-catalog.rst
.. _ADR 0034: 0034-permission-dependencies-in-authorization-schema.rst
.. _ADR 0035: 0035-custom-role-persistence.rst
.. _Issue #469: https://github.com/openedx/openedx-authz/issues/469

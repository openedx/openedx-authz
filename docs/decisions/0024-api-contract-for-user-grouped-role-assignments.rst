0024: API Contract for User-Grouped Role Assignments
#####################################################

Status
********

**Draft**

Context
*********

The new Figma design and product requirements for the Team Members tab in the
Admin Console change how assignments are presented: instead of listing one row
per assignment, the tab now groups assignments by user, showing one row per user
with their assignments nested underneath. The existing endpoints for gathering
user assignment data don't return all the fields this user-grouped view needs.
Before we can continue building it, we need to define a contract, either for a new
endpoint or for a backwards-compatible change to an existing one, that provides
those fields.

Following that design, the view displays a table of users. Each row shows the
username, email, a single scope the related assigned role, along with a control to
expand the row and reveal up to three assigned roles and the user's total number
of assigned roles.

The table can be searched by username, email, or full name; sorted by username or
full name; filtered by organization, role, or scope; and is paginated.

Decision
**********

Extend the existing /api/authz/v1/users/ endpoint, defined in TeamMembersAPIView,
to include a list of assignments for each user.

This endpoint was originally created for an earlier version of the Team Members
tab that was deprioritized and never implemented in a previous phase of the RBAC
project. At that time, the view did not expose each user's assigned roles, only a
total count.

As part of this change, the existing ``assignation_count`` field is renamed to
``assignment_count``. The rest of the repository consistently uses "assignment"
(e.g. ``RoleAssignmentData``, ``get_visible_role_assignments_for_user``, the
``/api/authz/v1/users/<username>/assignments/`` endpoint), so ``assignation_count``
is an inconsistent outlier. Renaming it now keeps the new user-grouped fields
(``assignments`` and ``assignment_count``) aligned with that convention. The field
is safe to rename because the ``GET /api/authz/v1/users/`` endpoint is not called
at all by
`frontend-app-admin-console <https://github.com/openedx/frontend-app-admin-console>`_,
the only client of the AuthZ API. Its current Team Members table is sourced from
the assignment-grouped ``GET /api/authz/v1/assignments/`` endpoint, so neither the
endpoint nor the ``assignation_count`` field has any released consumer.

The embedded assignments are not paginated. Each user includes only the first n
assignments, where n defaults to 3 and can be overridden by the assignments_limit
query parameter.


REST API for Team Members view
=================================

The existing /api/authz/v1/users/ endpoint will be extended to return a list of
assignments per user. The number of assignments returned is capped by the
assignments_limit parameter, which defaults to 3.

API Definition
--------------

GET /api/authz/v1/users/
^^^^^^^^^^^^^^^^^^^^^^^^^

Retrieve all users that have at least one role assignment (team members). Results
are filtered according to the calling user's scope-level view permissions.

Query Parameters:
"""""""""""""""""

-  ``scopes`` (optional): Comma-separated list of scopes to filter by (e.g.
   ``lib:Org1:LIB1``).
-  ``orgs`` (optional): Comma-separated list of orgs to filter by (e.g. ``Org1,Org2``).
-  ``search`` (optional): Search term to filter users by username, full name, or email.
-  ``assignments_limit`` (optional): Maximum number of assignments to populate in
   the ``assignments`` array for each user. Defaults to 3. The full total is always
   reported in ``assignment_count``.
-  ``sort_by`` (optional): Field to sort by. Options: ``username``, ``full_name``,
   ``email``. Defaults to ``username``.
-  ``order`` (optional): Sort order, ``asc`` or ``desc``. Defaults to ``asc``.
-  ``page`` (optional): Page number for pagination.
-  ``page_size`` (optional): Number of items per page.

Example:

.. code::

   GET /api/authz/v1/users/?orgs=Org1&search=john&assignments_limit=3&sort_by=username&order=asc&page=1&page_size=10

Response Body:
""""""""""""""

Format:

.. code:: ts

   {
       count: number
       next: string | null
       previous: string | null
       results: Array<{
           username: string
           full_name: string
           email: string
           assignment_count: number
           assignments: Array<{
               is_superadmin: boolean
               role: string
               org: string
               scope: string
               permission_count: number
           }>
       }>
   }

The ``assignments`` array is populated with up to ``assignments_limit`` entries
(default 3), while ``assignment_count`` always reflects the user's total number of
assignments regardless of the limit.

Example:

.. code:: json

   {
       "count": 2,
       "next": null,
       "previous": null,
       "results": [
           {
               "username": "jane_doe",
               "full_name": "Jane Doe",
               "email": "jane_doe@example.com",
               "assignment_count": 3,
               "assignments": [
                   {
                       "is_superadmin": false,
                       "role": "library_admin",
                       "org": "Org1",
                       "scope": "lib:Org1:LIB1",
                       "permission_count": 11
                   },
                   {
                       "is_superadmin": false,
                       "role": "library_user",
                       "org": "Org1",
                       "scope": "lib:Org1:LIB2",
                       "permission_count": 4
                   },
                   {
                       "is_superadmin": false,
                       "role": "library_admin",
                       "org": "Org2",
                       "scope": "lib:Org2:LIB1",
                       "permission_count": 11
                   }
               ]
           },
           {
               "username": "john_doe",
               "full_name": "John Doe",
               "email": "john_doe@example.com",
               "assignment_count": 1,
               "assignments": [
                   {
                       "is_superadmin": false,
                       "role": "library_user",
                       "org": "Org1",
                       "scope": "lib:Org1:LIB1",
                       "permission_count": 4
                   }
               ]
           }
       ]
   }

Possible response codes:
""""""""""""""""""""""""

-  200: Ok, includes the Response Body defined above.
-  400: Bad Request, happens when the request parameters are invalid.
-  401: Unauthorized, happens when the user is not authenticated/logged in.
-  403: Forbidden, happens when the user does not have the required permissions.

Consequences
************

- The existing /api/authz/v1/users/ endpoint will be extended to return the
  additional data: a nested ``assignments`` array per user and the renamed
  ``assignment_count`` field.
- Renaming ``assignation_count`` to ``assignment_count`` is technically a breaking
  change to the response body. It is low-risk here because
  frontend-app-admin-console does not call the ``GET /api/authz/v1/users/`` endpoint
  at all, so no released client depends on the field. Any internal tests or
  fixtures referencing ``assignation_count`` must still be updated.
- Both ``assignments`` and ``assignment_count`` reflect only the assignments the
  calling user is permitted to see, so values may differ between viewers for the
  same target user.
- The nested ``assignments`` array is truncated to ``assignments_limit`` and is
  not paginated. A follow-up is needed if the UI requires a defined order for the
  truncated entries, since no ordering is currently guaranteed within a user's
  assignments.


Rejected Alternatives
*********************

- Creating a new endpoint: The /api/authz/v1/users/ endpoint already provides most
  of the required logic, and it was originally created for this use case.
  Extending it is the simplest and most direct solution.

- Loading each user's assignments dynamically from the frontend after the initial
  /api/authz/v1/users/ response: This is suboptimal because it creates N+1 requests
  for a single page, increasing load time and placing unnecessary strain on the
  server.

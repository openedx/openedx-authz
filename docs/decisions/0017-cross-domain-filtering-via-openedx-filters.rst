0017: Cross-Domain Filtering via Open edX Filters
##################################################

Status
******

**Proposed** - *2026-07-31*

Context
*******

Casbin assignments may remain after ``authz.enable_course_authoring`` is disabled because the migration that synchronizes them is optional and does not cover every flag change (`ADR 0013`_). As a result, permission checks and role assignment requests may refer to a course that is no longer available in the authoring experience.

The Admin Console reads the flag state exposed in `ADR 0015`_ and filters course-authoring data before displaying it. This proposal leaves collection filtering in the Admin Console. Frontend filtering cannot protect role assignment writes or prevent permission validation from reporting an unavailable course as allowed.

These operations therefore need a backend extension point. Open edX Filters allows the views to expose authorization data to a separately configured pipeline, which keeps course-authoring state outside the shared authorization code and follows the boundary defined in `ADR 0016`_.

Decision
********

Add three operation-specific filters to the REST endpoints. The views pass data through their configured pipelines and continue with the returned data and errors. The course-authoring pipelines own visibility checks and rejection behavior.

The filters cover these operations:

* ``POST /validate/me/`` validates a user's permission in a scope.
* ``PUT /roles/users/`` assigns a role to users in one or more scopes.
* ``DELETE /roles/users/`` removes a role from users in a scope.

1. Filter contract
==================

Define one public filter for each operation:

* ``PermissionValidationRequested`` uses ``org.openedx.authz.permission_validation.requested.v1`` and receives computed permission results with ``action``, ``allowed``, and an optional ``scope``.
* ``RoleAssignmentRequested`` uses ``org.openedx.authz.role_assignment.requested.v1`` and receives validated ``role``, ``users``, and ``scopes`` before assignment writes.
* ``RoleRemovalRequested`` uses ``org.openedx.authz.role_removal.requested.v1`` and receives validated ``role``, ``users``, and ``scope`` before removal writes.

Each filter exposes the same calling convention with its own payload type:

.. code-block:: python

   PermissionValidationRequested.run_filter(items) -> (filtered_items, errors)
   RoleAssignmentRequested.run_filter(items) -> (filtered_items, errors)
   RoleRemovalRequested.run_filter(items) -> (filtered_items, errors)

Each filter passes its data through its independently configured pipeline. With no pipeline configured for that filter, it returns the original items and an empty error list.

Each filter has a defined input shape and can be configured independently.

The pipeline starts with an empty error list. Each step preserves errors from previous steps and appends its own.

The public contract leaves rejection rules to each pipeline, which decides which items to keep and which errors to return. For example, a pipeline may receive validated role assignment data for two scopes, retain the available scope, and return an error for the rejected operation:

.. code-block:: python

   items = {
       "role": "course_staff",
       "scopes": [
           "course-v1:Org1+VISIBLE101+2024",
           "course-v1:Org1+HIDDEN101+2024",
       ],
       "users": ["jane"],
   }

   filtered_items = {
       "role": "course_staff",
       "scopes": ["course-v1:Org1+VISIBLE101+2024"],
       "users": ["jane"],
   }

   errors = [
       {
           "user_identifier": "jane",
           "scope": "course-v1:Org1+HIDDEN101+2024",
           "error": "scope_not_available",
       }
   ]

The view writes only the operations in ``filtered_items`` and returns ``errors`` together with any errors raised during those writes. In this example, the course-authoring pipeline defines ``scope_not_available`` because the public filter does not define error values.

2. Permission validation
========================

``PermissionValidationMeView`` calls the filter after computing the permission results and before serializing the response. Because clients expect one result for every requested permission, the course-authoring pipeline keeps the item and changes ``allowed`` to ``False`` when its course scope is unavailable. An unscoped request remains unchanged because it does not provide a course for the pipeline to check.

For a user subject to visibility filtering, a request to ``POST /validate/me/`` with an unavailable course scope:

.. code-block:: json

   [
       {
           "action": "courses.view_course",
           "scope": "course-v1:Org1+HIDDEN101+2024"
       }
   ]

returns:

.. code-block:: json

   [
       {
           "action": "courses.view_course",
           "scope": "course-v1:Org1+HIDDEN101+2024",
           "allowed": false
       }
   ]

3. Role assignment writes
==========================

``RoleUserAPIView.put`` and ``RoleUserAPIView.delete`` call their filters after request validation and before writing any assignment. The views process the returned data and combine pipeline errors with errors from the role assignment APIs in their existing ``207 Multi-Status`` response.

For PUT, the course-authoring pipeline excludes unavailable scopes and returns one error for each rejected user and scope pair, as shown in the contract example. The view can still assign roles in the remaining scopes.

For example, ``PUT /roles/users/`` receives:

.. code-block:: json

   {
       "role": "course_staff",
       "scopes": [
           "course-v1:Org1+VISIBLE101+2024",
           "course-v1:Org1+HIDDEN101+2024"
       ],
       "users": ["jane"]
   }

If visibility filtering applies and the assignment in the available scope succeeds, the ``207 Multi-Status`` response is:

.. code-block:: json

   {
       "completed": [
           {
               "user_identifier": "jane",
               "scope": "course-v1:Org1+VISIBLE101+2024",
               "status": "role_added"
           }
       ],
       "errors": [
           {
               "user_identifier": "jane",
               "scope": "course-v1:Org1+HIDDEN101+2024",
               "error": "scope_not_available"
           }
       ]
   }

For DELETE, the pipeline returns an empty ``users`` list when the scope is unavailable and an error for each requested user, so the view performs no removals.

For example, ``DELETE /roles/users/?role=course_staff&scope=course-v1%3AOrg1%2BHIDDEN101%2B2024&users=jane`` returns the following ``207 Multi-Status`` response when visibility filtering applies:

.. code-block:: json

   {
       "completed": [],
       "errors": [
           {
               "user_identifier": "jane",
               "scope": "course-v1:Org1+HIDDEN101+2024",
               "error": "scope_not_available"
           }
       ]
   }

4. Course-authoring pipeline
============================

The course-authoring implementation lives in ``openedx_authz/rest_api/v1/course_authoring/pipeline.py``. Each operation has a separate pipeline step; the steps share visibility checks and error handling.

A deployment enables each operation independently in ``OPEN_EDX_FILTERS_CONFIG``:

.. code-block:: python

   OPEN_EDX_FILTERS_CONFIG = {
       "org.openedx.authz.permission_validation.requested.v1": {
           "pipeline": [
               "openedx_authz.rest_api.v1.course_authoring.pipeline.CourseAuthoringPermissionValidationFilter",
           ],
           "fail_silently": False,
       },
       "org.openedx.authz.role_assignment.requested.v1": {
           "pipeline": [
               "openedx_authz.rest_api.v1.course_authoring.pipeline.CourseAuthoringRoleAssignmentFilter",
           ],
           "fail_silently": False,
       },
       "org.openedx.authz.role_removal.requested.v1": {
           "pipeline": [
               "openedx_authz.rest_api.v1.course_authoring.pipeline.CourseAuthoringRoleRemovalFilter",
           ],
           "fail_silently": False,
       },
   }

This setting is typically added to edx-platform through a Tutor plugin patch. An operation without a configured pipeline retains its default behavior.

Once configured, the pipeline reads the effective ``authz.enable_course_authoring`` state for each course scope and leaves library scopes available.

Consequences
************

* Deployments must configure three filters to apply visibility rules to all three operations. Each operation can also be configured independently.
* Permission filtering happens after authorization checks, so it does not avoid the work of computing results that the pipeline later denies. Role changes are filtered before writes.
* ``openedx-filters`` becomes a runtime dependency of this repository.
* The course-authoring implementation can be removed with the flag while the public filters remain available for other authorization rules.

Alternatives Considered
***********************

Check the flag in each view
===========================

This would add course-authoring dependencies to shared authorization views and repeat the same check across the protected operations.

Protect writes in the frontend
==============================

Frontend checks control the Admin Console, but stale clients and direct API requests can still reach the write endpoints.

Filter collection responses in the API
======================================

The Admin Console already filters these responses using the exposed flag states. Backend collection filtering would also need to account for pagination and counts. This proposal is limited to permission validation and role changes.

Return a flag-specific response from the view
=============================================

``RoleUserAPIView`` already reports errors for each operation through ``207 Multi-Status``. The pipeline can use that response and keep flag-specific decisions out of the view.

References
**********

* `ADR 0013`_
* `ADR 0015`_
* `ADR 0016`_
* `Issue #363`_
* `PR #361`_

.. _ADR 0013: 0013-course-authoring-automatic-migration.rst
.. _ADR 0015: 0015-expose-course-authoring-waffle-flag-state-via-rest-api.rst
.. _ADR 0016: 0016-rest-api-domain-ownership-boundary.rst
.. _Issue #363: https://github.com/openedx/openedx-authz/issues/363
.. _PR #361: https://github.com/openedx/openedx-authz/pull/361

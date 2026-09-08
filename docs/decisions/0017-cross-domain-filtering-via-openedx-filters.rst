0017: Cross-Domain Filtering via Open edX Filters
##################################################

Status
******

**Proposed** - *2026-07-31*

Context
*******

Casbin assignments may remain after ``authz.enable_course_authoring`` is disabled because the migration that synchronizes them is optional and does not cover every flag change (`ADR 0013`_). As a result, permission checks and role assignment requests may refer to a course that is no longer available in the authoring experience.

The Admin Console reads the flag state exposed in `ADR 0015`_ and filters course-authoring data before displaying it. Since this behavior will remain while the flag is in use, collection endpoints do not need backend filtering. However, frontend filtering cannot protect role assignment writes or prevent permission validation from reporting an unavailable course as allowed.

These operations therefore need a backend extension point. Open edX Filters allows the views to expose authorization data to a separately configured pipeline, which keeps course-authoring state outside the shared authorization code and follows the boundary defined in `ADR 0016`_.

Decision
********

Call an Open edX Filter from the following operations:

* ``POST /validate/me/`` validates a user's permission in a scope.
* ``PUT /roles/users/`` assigns a role to users in one or more scopes.
* ``DELETE /roles/users/`` removes a role from users in a scope.

1. Filter contract
==================

Define the public ``AuthorizationDataRequested`` filter with the filter type ``org.openedx.authz.authorization_data.requested.v1`` and the following signature:

.. code-block:: python

   AuthorizationDataRequested.run_filter(items, user) -> (filtered_items, errors)

``items`` contains the authorization data being processed, and ``user`` is the authenticated Django user. The filter passes both values through the configured pipeline, then returns the filtered items and the errors produced by that pipeline. The caller continues its existing response or write logic with those values. If no pipeline is configured, the filter returns the original items and an empty error list.

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

For example, the endpoint may receive this request:

.. code-block:: json

   [
       {
           "action": "courses.view_course",
           "scope": "course-v1:Org1+HIDDEN101+2024"
       }
   ]

It then returns the following response:

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

``RoleUserAPIView.put`` and ``RoleUserAPIView.delete`` call the filter after request validation and before writing any assignment. The views iterate over the returned data, append the returned errors to any errors raised by the role assignment APIs, and use their existing ``207 Multi-Status`` response.

For PUT, the course-authoring pipeline removes unavailable scopes and returns one error for each rejected user and scope pair. This allows a request that contains both available and unavailable scopes to complete the available operations, as shown in the following request:

.. code-block:: json

   {
       "role": "course_staff",
       "scopes": [
           "course-v1:Org1+VISIBLE101+2024",
           "course-v1:Org1+HIDDEN101+2024"
       ],
       "users": ["jane"]
   }

The available operation succeeds, while the rejected operation appears in ``errors``:

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

DELETE accepts one scope, so the pipeline removes all users when that scope is unavailable and returns one error for each rejected user. For example, ``DELETE /roles/users/?role=course_staff&scope=course-v1%3AOrg1%2BHIDDEN101%2B2024&users=jane`` produces the same error entry as the PUT example and does not call the role removal API.

4. Course-authoring pipeline
============================

The course-authoring implementation lives in ``openedx_authz/rest_api/v1/course_authoring/pipeline.py``. A deployment enables it by registering its pipeline step under the public filter type in ``OPEN_EDX_FILTERS_CONFIG``:

.. code-block:: python

   OPEN_EDX_FILTERS_CONFIG = {
       "org.openedx.authz.authorization_data.requested.v1": {
           "pipeline": [
               "openedx_authz.rest_api.v1.course_authoring.pipeline.CourseAuthoringVisibilityFilter",
           ],
           "fail_silently": False,
       },
   }

This setting is typically added to edx-platform through a Tutor plugin patch. Without this entry, ``AuthorizationDataRequested`` returns the original data and an empty error list, so the endpoints keep their default behavior.

Once configured, the pipeline reads the effective ``authz.enable_course_authoring`` state for each course scope. It leaves library scopes available, while Django staff and superusers bypass the flag check.

Consequences
************

#. Shared views depend on the filter contract, while the pipeline owns the course-authoring rule.
#. PUT and DELETE reject unavailable scopes before calling the role assignment APIs.
#. ``PermissionValidationMeView`` reports an unavailable scoped permission with ``allowed`` set to ``false``.
#. Collection endpoints continue to return Casbin data, and the Admin Console filters their responses using the flag-state endpoint.
#. PUT may complete visible scope operations and report unavailable scopes in the same ``207 Multi-Status`` response.
#. Pipeline errors are part of the filter output, but their values are defined by each pipeline.
#. ``openedx-filters`` becomes a runtime dependency of this repository.
#. The pipeline can be removed with the course-authoring flag, while the public filter remains available for other authorization rules.

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

The Admin Console already filters these responses using the exposed flag states. Extending the backend filter to collection endpoints would add work to a temporary implementation and could change pagination and count behavior.

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

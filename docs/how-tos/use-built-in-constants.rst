Use Built-In Permission and Role Constants
##########################################

Import built-in permissions and roles from ``openedx_authz.authz``. Pass their external keys to the convenience functions in ``openedx_authz.api``:

.. code-block:: python

   from openedx_authz.api import assign_role_to_user_in_scope, is_user_allowed
   from openedx_authz.authz import COURSE_ADMIN, COURSES_VIEW_COURSE

   can_view_course = is_user_allowed(
       user_external_key="alice",
       action_external_key=COURSES_VIEW_COURSE.action.external_key,
       scope_external_key="course-v1:edX+DemoX+2026",
   )

   assign_role_to_user_in_scope(
       user_external_key="alice",
       role_external_key=COURSE_ADMIN.external_key,
       scope_external_key="course-v1:edX+DemoX+2026",
   )

Role constants identify roles without containing their complete permission lists. Use ``get_permissions_for_single_role`` or the compiled schema when a client needs to inspect the permissions assigned to a role.

See :doc:`Built-In Python Constants <../references/built-in-constants>` for the import and compatibility paths.

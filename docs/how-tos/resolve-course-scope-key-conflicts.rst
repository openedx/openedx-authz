Resolve Course Scopes That ``0013_remove_coursescope_course_overview`` Cannot Update
####################################################################################

Migration ``0013_remove_coursescope_course_overview`` copies the course key of each course scope created before ``0010_scope_external_key`` into ``external_key``, and then removes ``course_overview_id``. ``external_key`` is unique across all scopes, and MySQL compares it with the table collation, which ignores case and accents in ``utf8mb4_unicode_ci`` and ``utf8mb4_0900_ai_ci``, so a course key can collide with a key that another scope already holds. When that happens, the migration copies every other key and stops before it removes the column, with an error like this:

.. code-block:: text

   CourseScopeKeyConflictError: Cannot copy the course key of these course scopes into external_key, because another scope already holds an equal key: 12: course-v1:OpenedX+DemoX+2024. Resolve them as the openedx-authz how-to "Resolve Course Scopes That 0013_remove_coursescope_course_overview Cannot Update" describes, then run migrate again.

Each ``<scope id>: <course key>`` pair names a course scope whose key is still only in ``course_overview_id``. Since the database treats both keys as equal, both scopes refer to the same course, so the role assignments of the older scope move to the scope that holds the key, and the older scope is removed. Follow these steps for every pair in the error.

#. Back up the database.

#. Open a MySQL shell on the LMS database and find the scope that holds the key. This query returns its ``id``:

   .. code-block:: sql

      SELECT id, external_key FROM openedx_authz_scope
      WHERE external_key = 'course-v1:OpenedX+DemoX+2024';

#. List the role assignments of both scopes, to know what moves. Replace ``12`` with the scope from the error and ``34`` with the ``id`` from the previous step:

   .. code-block:: sql

      SELECT r.scope_id, c.v0 AS subject, c.v1 AS role, c.v2 AS scope
      FROM openedx_authz_extendedcasbinrule r
      JOIN casbin_rule c ON c.id = r.casbin_rule_id
      WHERE r.scope_id IN (12, 34);

#. Move the role assignments of the older scope to the scope that holds the key, and remove the older scope:

   .. code-block:: sql

      UPDATE openedx_authz_extendedcasbinrule SET scope_id = 34 WHERE scope_id = 12;
      DELETE FROM openedx_authz_coursescope WHERE scope_ptr_id = 12;
      DELETE FROM openedx_authz_scope WHERE id = 12;

#. Run ``./manage.py lms migrate`` again, which copies only the keys that are still missing and then removes ``course_overview_id``.


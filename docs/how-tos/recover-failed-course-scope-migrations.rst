Recover From Failed Course Scope Migrations
###########################################

Recover From a Failed ``0007_coursescope`` Migration
****************************************************

Releases of openedx-authz before the fix for `issue #593`_ could stop ``./manage.py lms migrate`` at ``openedx_authz.0007_coursescope`` on MySQL databases whose default collation is not ``utf8mb4_unicode_ci``, such as the MySQL 8 default ``utf8mb4_0900_ai_ci``. The error looks like this:

.. code-block:: text

   django.db.utils.OperationalError: (3780, "Referencing column 'course_overview_id' and referenced column 'id' in foreign key constraint 'openedx_authz_course_course_overview_id_e73fe24b_fk_course_ov' are incompatible.")

MySQL does not run schema changes inside a transaction (see `Django migrations on MySQL`_), so the failed run leaves the ``openedx_authz_coursescope`` table behind without recording ``0007`` as applied. Every later ``migrate`` then fails with ``(1050, "Table 'openedx_authz_coursescope' already exists")``. Follow these steps to remove that table and apply the fixed migration.

#. Back up the database.

#. Open a MySQL shell on the LMS database and confirm that ``0007`` is not recorded as applied. This query must return no rows:

   .. code-block:: sql

      SELECT name FROM django_migrations
      WHERE app = 'openedx_authz' AND name = '0007_coursescope';

#. Confirm that the table is empty. This query must return ``0``:

   .. code-block:: sql

      SELECT COUNT(*) FROM openedx_authz_coursescope;

   Stop here if either check fails, because the database is not in the state this procedure covers.

#. Drop the table:

   .. code-block:: sql

      DROP TABLE openedx_authz_coursescope;

#. Upgrade openedx-authz to 1.23.1 or later, which includes the fix, and run ``./manage.py lms migrate`` again.

.. _issue #593: https://github.com/openedx/openedx-authz/issues/593
.. _Django migrations on MySQL: https://docs.djangoproject.com/en/5.2/topics/migrations/#mysql

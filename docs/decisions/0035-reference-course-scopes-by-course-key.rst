0035: Reference Course Scopes by Course Key
###########################################

Status
******

**Draft**

Context
*******

Migration ``0007_coursescope`` fails with MySQL error 3780 on databases whose default collation is ``utf8mb4_0900_ai_ci``, as on MySQL 8 and AWS RDS, which blocks the upgrade to Verawood on those instances (`Issue #593`_). On MySQL, a foreign key between string columns needs the same character set and collation on both columns (`MySQL foreign key constraints`_), while the two columns of the ``CourseScope`` foreign key end up with different ones, because ``course_overview_id`` gets ``utf8mb4_unicode_ci``, which opaque key fields declare since `opaque-keys#426`_, and ``course_overviews_courseoverview.id`` keeps the collation the database had when the platform created the table. `PR #626`_ fixes the upgrade by giving ``course_overview_id`` the collation of the column it references before ``0007`` creates the foreign key, so the upgrade succeeds while the foreign key and the dependency it carries stay.

`ADR 0005`_ added that foreign key so that deleting a course also deletes its scope and the role assignments on it. Since migration ``0010_scope_external_key``, every new scope also stores its course key in ``Scope.external_key``, and the code that reads the course of a scope (the scope data's object lookup, display names and the admin console) starts from that key, so the foreign key is left with three jobs:

* Deleting the scope when its course is deleted.
* Finding the scope of an existing course when a role is assigned on it.
* Linking a scope created for a course key to its course once the course is created.

The foreign key is also where the framework still depends on how openedx-platform models courses. `ADR 0001`_ sets out to develop authorization separately from the platform so that this repository can become a reusable Django library, and `ADR 0032`_ keeps the reusable framework apart from the Open edX-specific definitions it ships, whereas the course scope model, its migrations and its signal handlers reference the platform's ``CourseOverview`` model, and the foreign key carries that dependency down to the database schema, where the collation failure appears.

Decision
********

``CourseScope`` references its course only through the course key in ``Scope.external_key``, with no foreign key to the ``CourseOverview`` model, so the framework's schema no longer depends on the platform's course table.

1. Course key as the only reference
===================================

``external_key`` holds the course key in its string form, for example ``course-v1:OpenedX+DemoX+2024``, and scopes are created and found by that key whether the course exists or not. A role assigned on a course key before the course is created, as during a course rerun, therefore creates the same scope that later lookups find, and nothing has to link the two once the course exists.

2. Reading the course from a scope
==================================

``CourseScope.course_overview`` becomes a read-only property that looks up the course by ``external_key`` and returns ``None`` while the course does not exist, so code that reads the course from a scope keeps working. Code that filtered scopes by course or read the reverse accessor uses the key instead:

.. code-block:: python

   # Before
   CourseScope.objects.filter(course_overview=course)
   course.authz_scopes.all()

   # After
   CourseScope.objects.filter(external_key=str(course.id))

3. Deleting a course
====================

A receiver on the ``post_delete`` signal of the model named by ``OPENEDX_AUTHZ_COURSE_OVERVIEW_MODEL`` deletes the course scope whose ``external_key`` equals the deleted course key, and the delete then follows the existing chain, so a course deleted through Django loses the same rows that the foreign key cascade deleted:

.. code-block:: text

   CourseOverview deleted
     -> CourseScope            post_delete receiver, by external_key
       -> ExtendedCasbinRule   cascade on ExtendedCasbinRule.scope
         -> CasbinRule         existing receiver on ExtendedCasbinRule

Like the existing ``post_save`` receivers, it is connected only when that model is installed, and it also runs for queryset deletes, since Django sends ``post_delete`` for each deleted object.

4. Removing the column
======================

Migration ``0013_remove_coursescope_course_overview`` brings every instance to the same schema. It first copies ``course_overview_id`` into ``external_key`` for each course scope whose key is empty, which only scopes created before ``0010_scope_external_key`` can have:

.. list-table::
   :header-rows: 1

   * - ``course_overview_id``
     - ``external_key`` before
     - ``external_key`` after
   * - ``course-v1:OpenedX+DemoX+2024``
     - empty
     - ``course-v1:OpenedX+DemoX+2024``
   * - empty
     - ``course-v1:OpenedX+Rerun+2025``
     - unchanged

On MySQL, the unique ``external_key`` compares keys with the table collation, which ignores case and accents in ``utf8mb4_unicode_ci`` and ``utf8mb4_0900_ai_ci``, so a copied key can collide with the key of another scope. Each copy is therefore a separate update, and when a copy collides the migration still copies the other keys, then lists the conflicting scopes in its error and stops, so the column is never removed while a course key exists only there.

``RemoveField`` then removes the column, and since Django looks up the column's foreign key constraints in the database before removing it, it also drops the constraint that ``0007`` created.

5. Content library scopes
=========================

``ContentLibraryScope`` keeps its foreign key to the ``ContentLibrary`` model, whose primary key is an integer and has no collation problem, so the same change for library scopes is a separate decision.

Consequences
************

* The ``openedx_authz`` schema has no constraint on the platform's course table, and the code that linked a scope to a course created after it goes away, so the framework's data model depends on courses only through their keys.
* Deleting a course through Django still deletes its scope and role assignments, whereas a course row removed with raw SQL leaves them in place, since no signal runs and no constraint blocks that delete, and a course created later with the same key inherits them.
* Filtering or creating scopes with ``course_overview`` and the reverse accessor ``CourseOverview.authz_scopes`` no longer work, so the change is released as a breaking change, while the ``CourseScope.course_overview`` property keeps working for code that only reads the course.
* When migration ``0013`` reports conflicting scopes, an operator has to resolve them before running ``migrate`` again.
* Instances whose course table has a different collation cannot migrate back below ``0013``, because reversing it adds the foreign key back and fails with error 3780.
* Course and library scopes reference their objects in different ways, and the framework still depends on the platform's ``ContentLibrary`` model. Library scopes created since ``0010_scope_external_key`` also store their library key in ``Scope.external_key``, so the same change, with the same backfill for older scopes, can remove that last foreign key from a scope to a platform model.
* Once course and library scopes reference their objects only by key, the only code that depends on the platform's models is the receiver and the property of each scope type, so those scope types could move out of the framework core into the code that owns those models, and each move needs its own decision.

Rejected Alternatives
*********************

Align the collation and keep the foreign key
============================================

Aligning the collation fixes the upgrade, which is why `PR #626`_ does it in ``0007``, but keeping the foreign key afterwards keeps the framework's schema tied to the platform's course table.

Keep the field without a database constraint
============================================

A ``ForeignKey`` with ``db_constraint=False`` avoids the error, but keeps the field, the code that links a scope to a course created after it, and the reference to the platform model in the migration state.

Change the collation of the platform's course table
===================================================

The table belongs to the platform, and changing it from this repository affects every other table that references it.

References
**********

* `ADR 0001`_
* `ADR 0005`_
* `ADR 0032`_
* `Issue #593`_
* `PR #626`_
* `opaque-keys#426`_
* `MySQL foreign key constraints`_

.. _ADR 0001: 0001-purpose-of-this-repo.rst
.. _ADR 0005: 0005-architecture-and-data-modeling.rst
.. _ADR 0032: 0032-applets-for-built-in-authorization-capabilities.rst
.. _Issue #593: https://github.com/openedx/openedx-authz/issues/593
.. _PR #626: https://github.com/openedx/openedx-authz/pull/626
.. _opaque-keys#426: https://github.com/openedx/opaque-keys/pull/426
.. _MySQL foreign key constraints: https://dev.mysql.com/doc/refman/8.0/en/create-table-foreign-keys.html

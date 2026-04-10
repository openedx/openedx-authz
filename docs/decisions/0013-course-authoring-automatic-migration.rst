0013: Course Authoring - Automatic Migration Triggered by Course Authoring Flag
###############################################################################

Status
******

**Draft** - *2026-04-09*

Context
*******

The system is transitioning from the legacy permissions model (``CourseAccessRole``)
to the new openedx-authz system.

Currently, migrations between both systems are performed manually using Django management commands:

- ``authz_migrate_course_authoring`` (forward migration)
- ``authz_rollback_course_authoring`` (rollback migration)

In `ADR 0011`_ and `ADR 0010`_ it was established that migration must occur automatically when
the feature flag ``authz.enable_course_authoring`` changes state, but the definition of
the specific mechanism was deferred. This ADR addresses that gap.

The current manual approach presents the following risks:

- **Inconsistency**: If an operator enables or disables the flag without running the migration
  command, the permission data in both systems will diverge.
- **No status tracking**: There is no visibility into whether a migration is in progress,
  completed, or failed.
- **No concurrency protection**: Nothing prevents operators from running the migration command
  multiple times simultaneously, which can lead to race conditions and data corruption.
- **No user feedback**: Operators have no way to know the result of a migration without
  inspecting logs manually.

Decision
********

We will implement an automatic and asynchronous migration mechanism triggered by changes in the
``authz.enable_course_authoring`` feature flag. The solution consists of:

#. Django signal handler to detect flag state changes.
#. Celery tasks to execute migrations asynchronously.
#. A tracking model to record migration status and errors.
#. A locking mechanism to prevent concurrent migrations on the same scope.

.. note::

  **Scope Constraint**

  Automatic migration will only trigger for **course-level** and **organization-level** flag
  overrides, not for global (instance-wide) Waffle flag changes. The reason is that a global
  flag change could affect a large number of courses simultaneously, introducing an unacceptable
  performance risk. Global flag changes must be handled via management commands by operators
  who explicitly accept the performance implications.

Operator Safety and Opt-in Design
==================================

A concern was raised about the risks of triggering data migrations on a live instance. Data
migrations are typically executed under controlled conditions (e.g., during maintenance windows)
because any failure can leave the system in an invalid state. Triggering them automatically via
a feature flag toggle introduces additional risk:

- Django Admin access is sometimes granted to instructors or non-technical staff who may not
  understand the implications of toggling the flag.
- A live instance may be processing requests concurrently, increasing the chance of partial
  failures or inconsistent transient states.

To address this, the automatic migration mechanism will be **guarded by a Django setting**:

.. code:: python

    ENABLE_AUTOMATIC_AUTHZ_COURSE_AUTHORING_MIGRATION = False

This setting:

- Is **disabled by default**.
- Must be explicitly set to ``True`` by a site operator who understands the migration risks.
- Acts as a prerequisite check inside the signal handler: if it is not enabled, the signal
  detects the flag change but does **not** dispatch the Celery task. The operator must then
  run the migration manually using the existing management commands.

This design preserves the automated behavior for operators who opt in while keeping the system
safe for deployments where uncontrolled migrations are unacceptable.

Detailed Design
===============

1. Utility Function Updates
---------------------------

The existing utility functions ``migrate_legacy_course_roles_to_authz`` and
``migrate_authz_to_legacy_course_roles`` will be modified to incorporate the locking strategy
(see **Concurrency Control** below) and the tracking logic (see **Migration Tracking Model** below)
as integral steps of their execution.

This approach ensures that both the Celery task and the management commands go through the same
tracking and locking path.

2. Migration Trigger (Django Signals)
-------------------------------------

``pre_save`` signal handlers are attached to ``WaffleFlagCourseOverrideModel`` and
``WaffleFlagOrgOverrideModel``. When a save is detected for the ``authz.enable_course_authoring``
flag, the handler:

#. Compares the previous and new flag state to determine the transition direction:

   - ``False → True``: triggers a **forward migration** (Legacy → openedx-authz)
   - ``True → False``: triggers a **rollback migration** (openedx-authz → Legacy)

#. Determines the scope (course or organization) from the model being saved.
#. Dispatches an asynchronous Celery task with the migration parameters.

.. note::
  If no effective change is detected (i.e., the flag state is the same as the previous state),
  the signal handler does nothing.

3. Migration Tracking Model
---------------------------

A new model is introduced to track the lifecycle of each migration operation:

.. code:: python

    class AuthzCourseAuthoringMigrationRun(models.Model):
        migration_type = models.CharField(max_length=20)  # forward / rollback
        scope_type = models.CharField(max_length=20)  # course / org
        scope_key = models.CharField(max_length=255)
        status = models.CharField(max_length=20)  # pending, running, completed, skipped
        created_at = models.DateTimeField(auto_now_add=True)
        updated_at = models.DateTimeField(auto_now=True)
        completed_at = models.DateTimeField(null=True, blank=True)
        metadata = models.JSONField(default=dict)

This model is registered in Django Admin so operators can inspect migration history and
diagnose failures without needing to access logs directly.

4. Asynchronous Execution
-------------------------

The Celery task acts strictly as a thin dispatcher. All core logic, including locking,
tracking, and migration execution, is implemented in the utility functions (see
**Utility Function Updates** above).

All database operations within the migration itself execute inside an atomic transaction.
If the migration fails, no data is deleted from either system, preserving consistency.

5. Concurrency Control (Locking Strategy)
-----------------------------------------

To prevent race conditions caused by rapid or concurrent flag changes on the same scope, a
distributed lock is implemented using the Django cache backend (Redis):

.. code:: python

    lock_key = f"authz_migration:{scope_type}:{scope_key}"

The lock is acquired using ``cache.add()``, which is an atomic operation. The default TTL
is **1 hour**. If a lock already exists for the given scope, the migration is skipped
and a new tracking record is created with that status. This ensures that only one
migration runs at a time for the same scope.

6. Execution Flow
------------------

1. An operator changes the ``authz.enable_course_authoring`` flag for a course or
   organization via Django Admin or a management command.
2. The ``pre_save`` signal handler detects the state transition.
3. A Celery task is dispatched asynchronously.
4. The task calls the utility function, which acquires the lock, creates and updates the
   ``AuthzCourseAuthoringMigrationRun`` record, and executes the migration.
5. The operator can check the migration status via Django Admin on the ``AuthzCourseAuthoringMigrationRun``
   model.

Consequences
************

Positive consequences
=====================

- **Migration is decoupled from the request cycle**: the flag change returns immediately and
  migration happens in the background.
- **Full observability**: every migration run is recorded with its status, scope, and metadata
  in the tracking model.
- **Concurrency-safe**: the lock strategy prevents overlapping migrations on the same scope.
- **No manual intervention required**: for course-level or organization-level flag changes. Operators
  who have opted in do not need to remember to run management commands.
- **Safe by default**: the opt-in guard flag ensures that automatic migration is never triggered
  unexpectedly on instances where operators have not explicitly accepted the risks.

Negative consequences / risks
==============================

- **Global flag changes are not covered**: operators must still run management commands
  manually when enabling or disabling the flag at the instance level. This is a deliberate
  trade-off to avoid performance risks.
- **Celery dependency**: the system now requires a functioning Celery worker for automatic
  migration. If workers are down, migrations will be queued but not executed until workers
  recover.
- **Lock TTL edge cases**: if a migration takes longer than 1 hour (unlikely but possible
  for very large organizations), the lock will expire and a new migration for the same scope
  could start concurrently for the same scope.

Rejected Alternatives
*********************

**Synchronous execution in the signal handler**
  Executing the migration directly inside the ``pre_save`` signal would block the HTTP
  request that triggered the flag change, leading to timeouts for large scopes and poor
  operator experience.

**Manual migration**
  Error-prone, not scalable, and inconsistent. The flag is the source of truth, but manual
  migration allows the system to end up in inconsistent states (e.g., flag enabled but data
  still in the legacy system), resulting in an operationally fragile design.

**Automatic global migration**
  Triggering automatic migration when the flag is changed globally (instance-wide) would
  risk performance degradation on large instances. This was explicitly ruled out: global
  migrations must remain operator-initiated via management commands.

References
**********

* `Automatic Migration Spike`_
* `ADR 0010`_
* `ADR 0011`_

.. _Automatic Migration Spike:
   https://openedx.atlassian.net/wiki/spaces/OEPM/pages/6205112321/Spike+-+RBAC+AuthZ+-+Automatic+Role+Migration
.. _ADR 0010: 0010-course-authoring-flag.rst
.. _ADR 0011: 0011-course-authoring-migration-process.rst

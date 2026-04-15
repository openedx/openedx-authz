0013: Course Authoring - Automatic Migration Triggered by Course Authoring Flag
###############################################################################

Status
******

**Draft** - *2026-04-13*

Context
*******

The system is transitioning from the legacy permissions model (``CourseAccessRole``)
to the new openedx-authz system.

Currently, migrations between the two systems are performed manually using Django
management commands:

- ``authz_migrate_course_authoring`` (forward migration)
- ``authz_rollback_course_authoring`` (rollback migration)

In `ADR 0010`_ and `ADR 0011`_ it was established that migrations must occur automatically when
the feature flag ``authz.enable_course_authoring`` changes state, but the definition of
the specific mechanism was deferred. This ADR addresses that gap.

The current manual approach has the following problems:

- **Access disparity**: Many users have access to Django Admin and can toggle the flag, while
  significantly fewer have permission to run management commands. This creates an operational
  gap where the flag state can change independently of the migration process. As a result,
  coordination is required between different roles (those managing flags vs. those executing
  migrations), increasing the risk of delays, misalignment, and inconsistent system state.
- **Outage window**: When a flag change and the corresponding migration command are not executed
  atomically, there is a period where the flag points to one system but the permission data
  still lives in the other. Any permission check made during this window will fail, causing
  real outages for affected courses or organizations.
- **No user feedback**: Users have no way to know the result of a migration without
  inspecting logs manually.
- **No concurrency protection**: Nothing prevents operators from running the migration command
  multiple times simultaneously, which can lead to race conditions and data corruption.

Decision
********

We will implement an automatic and synchronous migration mechanism triggered by changes in the
``authz.enable_course_authoring`` feature flag. The solution consists of:

#. A ``post_save`` signal handler that detects flag changes and executes the migration.
#. A tracking model to record migration status and errors.
#. A database-level constraint to prevent concurrent migrations on the same scope.

.. note::

  **Scope Constraint**

  Automatic migration will only trigger for **course-level** and **organization-level** flag
  overrides, not for global (instance-wide) Waffle flag changes. The reason is that a global
  flag change could affect a large number of courses simultaneously, introducing an unacceptable
  performance risk. Global flag changes must be handled via management commands by operators
  who explicitly accept the performance implications.

Operator Safety and Opt-in Design
=================================

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
  detects the flag change but does not execute the migration. The operator must then
  run the migration manually using the existing management commands.

Detailed Design
===============

1. Migration Trigger (Django Signals)
-------------------------------------

A ``post_save`` handler is attached to ``WaffleFlagCourseOverrideModel`` and
``WaffleFlagOrgOverrideModel`` for the ``authz.enable_course_authoring`` flag.

The handler fires after the record is committed to the database, so the new flag value is
the authoritative and durable state of the system when the migration begins.

Retrieving the previous state from the same model
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Both ``WaffleFlagCourseOverrideModel`` and ``WaffleFlagOrgOverrideModel`` extend
``ConfigurationModel``, which **creates a new row on every save** instead of updating the
existing record. This means the full change history for each scope is preserved in the
table. The previous override value is therefore always available as the most recent record
for the same scope that is not the one just saved.

If no previous record exists for the scope (this is the first override ever created for
it), the migration runs unconditionally based on the current ``enabled`` value, without
comparing against a previous state.

``post_save`` execution
~~~~~~~~~~~~~~~~~~~~~~~

The ``post_save`` handler:

#. Queries the same flag override model for the previous record as described above.
#. If no previous record exists, runs the migration based on the current ``enabled`` value
   without further comparison.
#. If a previous record exists, compares its ``enabled`` value with the saved one to
   determine whether an effective transition occurred:

   - ``False → True``: triggers a **forward migration** (Legacy → openedx-authz)
   - ``True → False``: triggers a **rollback migration** (openedx-authz → Legacy)
   - No change: the handler does nothing. No tracking record is created and no migration runs.

#. Determines the scope (course or organization) from the model being saved.
#. Calls the utility function synchronously with the migration parameters.

2. Migration Tracking Model
---------------------------

A new model is introduced to track the lifecycle of each migration operation:

.. code:: python

    class AuthzCourseAuthoringMigrationRun(models.Model):
        migration_type = models.CharField(max_length=20)  # forward / rollback
        scope_type = models.CharField(max_length=20)  # course / org
        scope_key = models.CharField(max_length=255)
        status = models.CharField(max_length=20)  # running, completed, partial_success, failed, skipped
        created_at = models.DateTimeField(auto_now_add=True)
        updated_at = models.DateTimeField(auto_now=True)
        completed_at = models.DateTimeField(null=True, blank=True)
        metadata = models.JSONField(default=dict)

This model is registered in Django Admin so users can inspect migration history and
diagnose failures without needing to access logs directly.

A higher-level orchestration layer (separate from the existing utility functions) will be
responsible for creating and updating ``AuthzCourseAuthoringMigrationRun`` records. This
layer wraps the core migration logic, ensuring that lifecycle tracking (opening a
``running`` record, handling errors, and writing the final status) is applied consistently
regardless of whether the migration is triggered by the signal handler or a management
command.

Migration Outcome Semantics
~~~~~~~~~~~~~~~~~~~~~~~~~~~

The ``status`` field reflects the precise outcome of each run. The possible values are:

- ``running``: the migration is actively executing.
- ``completed``: all records were migrated successfully. The ``metadata`` field contains the
  details about the successful migrations.
- ``partial_success``: the migration process ran to completion, but one or more individual
  records failed and were skipped. The ``metadata`` field contains details about the
  failures and successfully migrated records.
- ``failed``: a critical error prevented the migration from completing (e.g., an unhandled
  exception or infrastructure problem). The ``metadata`` field contains the exception details.
- ``skipped``: the migration was not attempted because another run for the same scope was
  already active.

3. Concurrency Control
----------------------

To prevent overlapping migrations on the same scope, the tracking model enforces a
conditional ``UniqueConstraint`` on ``(scope_type, scope_key)`` filtered to
``status="running"``. This guarantees that no second active migration record can be
inserted for the same scope regardless of how many processes attempt to do so concurrently.
Any attempt raises an ``IntegrityError``, which the caller handles by recording a
``skipped`` run and aborting.

.. code:: python

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["scope_type", "scope_key"],
                condition=models.Q(status="running"),
                name="unique_active_migration_per_scope",
            )
        ]

4. Execution Flow
-----------------

1. The user changes the ``authz.enable_course_authoring`` flag for a course or
   organization and saves the record. A new row is created in the override table.
2. The ``post_save`` handler queries the same override model for the previous record
   (most recent row for the same scope, excluding the one just saved) to obtain the
   previous ``enabled`` value.
3. The handler compares the previous value with the current ``enabled`` value. If no
   effective change occurred, it does nothing.
4. If a transition is detected, the handler calls the utility function synchronously. The
   function creates an ``AuthzCourseAuthoringMigrationRun`` record with
   ``status="running"`` (the database constraint prevents this if another run for the
   same scope is already active) and executes the migration.
5. The record is updated to its final status (``completed``, ``partial_success``, ``failed``,
   or ``skipped``) before the ``post_save`` handler returns.
6. The user can review the migration outcome via Django Admin on the
   ``AuthzCourseAuthoringMigrationRun`` model.

Consequences
************

Positive consequences
=====================

- **Full observability**: every migration run is recorded with its status, scope, and metadata
  in the tracking model.
- **Concurrency-safe**: the database-level constraint prevents overlapping migrations on the same
  scope, regardless of cache availability or worker failures.
- **No manual intervention required** for course-level or organization-level flag changes. Operators
  or users who have opted in do not need to remember to run management commands.
- **Safe by default**: the opt-in guard flag ensures that automatic migration is never triggered
  unexpectedly on instances where operators have not explicitly accepted the risks.

Negative consequences / risks
=============================

- **Global flag changes are not covered**: operators must still run management commands
  manually when enabling or disabling the flag at the instance level. This is a deliberate
  trade-off to avoid performance risks.
- **Blocks the request**: the migration runs synchronously inside the ``post_save`` signal,
  so the HTTP request that triggered the flag change does not return until the migration
  finishes. For large organization-level scopes this can cause noticeable latency or
  timeouts. This is an accepted trade-off given that automatic migration is scoped to
  course-level and organization-level overrides only (never global), and is opt-in.
- **Runtime execution trade-offs**: Unlike management commands typically executed during
  maintenance windows, this migration runs in a live production environment as part of
  normal system operation. This means it executes under concurrent load, with active
  requests and database activity, which introduces variability in execution conditions.
  This trade-off is inherent to enabling the feature flag to act as a real-time source
  of truth. The design prioritizes consistency between flag state and permission data
  over strictly controlled execution environments, while providing observability and
  recovery mechanisms to mitigate operational risk.

Rejected Alternatives
*********************

**Using pre_save to trigger the migration**
  The use of pre_save signals was discarded because they depend on a state transition
  that has not yet been committed to the database. Operating before persistence assumes
  a future-valid state that may not materialize. post_save was preferred to ensure
  migration logic operates only on confirmed states.

**Asynchronous execution via Celery**
  Given that automatic migration is scoped to course-level and organization-level
  overrides where migration volumes are bounded, synchronous execution is simpler
  and provides stronger consistency guarantees.

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

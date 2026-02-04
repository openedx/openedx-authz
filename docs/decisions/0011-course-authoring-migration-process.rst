0011: AuthZ for Course Authoring - Migration Process Details
#############################################################

Status
******

**Draft**

Context
*******

The legacy course authoring roles and permissions system stores role assignments in the
MySQL ``student_courseaccessrole`` table, represented by the `CourseAccessRole model`_.

To preserve existing role assignments during the transition to the new openedx-authz system,
we need a bidirectional data migration process that:

- Supports course, organization, and instance-level migrations (compatible with the feature
  flag functionality in `ADR 0010`_)
- Enables rollback capability when the feature flag is disabled
- Maintains data consistency by removing role assignments from the source system after
  migration
- Ignores roles that exist in the new system but have no legacy equivalent

*Note: New system roles without legacy equivalents will be preserved but not enforced until
the flag is re-enabled.*


Decision
********

**Automatic Migration Triggers**

Migration occurs immediately when the feature flag state changes:

- **Flag enabled**: Legacy role assignments migrate to new system and are removed from
  legacy system
- **Flag disabled**: New system role assignments migrate to legacy system and are removed
  from new system

*Note: Roles without legacy equivalents remain in the new system and are not migrated*

**Forward Migration Process** (Legacy → openedx-authz)

- **Parameters**: Optional course or organization filter
- **Process**:

  1. Query CourseAccessRole instances matching the specified filter (or all if no filter)
  2. Create equivalent role assignments in openedx-authz for each CourseAccessRole
  3. Remove successfully migrated CourseAccessRole instances
  4. Execute within database transaction for consistency

**Rollback Migration Process** (openedx-authz → Legacy)

- **Parameters**: Optional course or organization filter
- **Process**:

  1. Query openedx-authz role assignments for specified scope (or all course authoring
     roles)
  2. Create equivalent CourseAccessRole assignments for roles with legacy equivalents
  3. Log warnings for roles without legacy equivalents (these remain in openedx-authz)
  4. Remove successfully migrated openedx-authz assignments
  5. Execute within database transaction for consistency

**Role Mapping**

The following role equivalences define the migration logic:

+----------------------------------+---------------------------+
| Legacy Role (internal name)      | New AuthZ Role*           |
+==================================+===========================+
| Admin (instructor)               | Course Admin              |
+----------------------------------+---------------------------+
| Staff (staff)                    | Course Staff              |
+----------------------------------+---------------------------+
| Limited Staff (limited_staff)    | Course Limited Staff      |
+----------------------------------+---------------------------+
| Course Data Researcher           | Course Data Researcher    |
| (data_researcher)                |                           |
+----------------------------------+---------------------------+
| Beta Testers (beta_testers)      | Course Beta Tester        |
+----------------------------------+---------------------------+

*New AuthZ role names are subject to change.*

**Execution Methods**

**Automatic Execution**
  Django ``pre_save`` signal handlers trigger migration when flag state changes via Django
  Admin or management commands. See `Authoring Waffle Flag Implementation Spike`_ for details.

**Management Commands**

  *Flag Management (triggers automatic migration):*

  - Enable globally: ``./manage.py cms waffle_switch authz.enable_course_authoring on
    --create``
  - Disable globally: ``./manage.py cms waffle_switch authz.enable_course_authoring off``

  *Manual Migration (for debugging):*

  - Forward migration: ``./manage.py cms authz_migrate_course_authoring
    [course_key|org_name]``
  - Rollback migration: ``./manage.py cms authz_rollback_course_authoring
    [course_key|org_name]``


Consequences
************

- Comprehensive migration documentation will be created for site operators
- Database transactions ensure data consistency during migration operations
- Site operators must test migration processes before legacy system deprecation
- Automatic migration will execute for remaining courses when the feature flag is
  deprecated post-Willow (Specific mechanism for automatic execution will be defined later)

Rejected Alternatives
*********************

**Instance-level migration only**
  Prevents granular testing on individual courses or organizations, increasing adoption
  risk.

**Management command-only approach**
  Creates operational overhead and increases risk of inconsistent role assignments during
  transition.

**Dual-write approach**
  Maintaining role assignments in both systems simultaneously would create data
  synchronization complexity and potential inconsistencies.

**Copy-only migration**
  Keeping role assignments in both systems would lead to data duplication, confusion about
  source of truth, and potential security risks.

**No rollback capability**
  Would make migration irreversible and increase adoption risk for site operators.

References
**********

* `Understand current course authoring roles and permissions logic Spike`_
* `Authoring Waffle Flag Implementation Spike`_
* `CourseAccessRole model`_
* `ADR 0010`_


.. _Understand current course authoring roles and permissions logic Spike:
   https://openedx.atlassian.net/wiki/spaces/OEPM/pages/5639602177/Spike+-+RBAC+AuthZ
   +-+Understand+current+course+authoring+roles+and+permissions+logic+and+propose+reusable
   +solution
.. _CourseAccessRole model:
   https://github.com/openedx/edx-platform/blob/e6deac0cf12226c0b8d744ad17395373cfe0de03
   /common/djangoapps/student/models/user.py#L1046
.. _ADR 0010:
   https://github.com/openedx/openedx-authz/blob/main/docs/decisions/0010-course-authoring
   -flag.rst
.. _Authoring Waffle Flag Implementation Spike:
   https://openedx.atlassian.net/wiki/spaces/OEPM/pages/5646221313/Spike+-+RBAC+AuthZ+-+
   Authoring+Waffle+Flag+Implementation

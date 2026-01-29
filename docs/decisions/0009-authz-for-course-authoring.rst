0009: AuthZ for Course Authoring Implementation Plan
####################################################

Status
******

**Draft**

Context
*******

Phase 2 of the RBAC AuthZ Project implements the openedx-authz system for the Course Authoring
experience in Studio, enabling new permissions and roles for course management.

For more information on this project, see: `PRD Authz for Course Authoring`_


Tech Debt
---------

Long-term, the openedx-authz architecture aims to be easily extensible, allowing third-party
modules to define their own permissions and roles without modifying the openedx-authz repository.

However, the architecture for externalized permissions is still under development. Therefore, for
this phase, permissions and roles will be temporarily implemented directly in openedx-authz,
following the same approach used for Libraries in Phase 1.

Once the architecture for externalized permissions is ready, follow-up tasks will address this
technical debt.

A feature flag will be implemented in openedx-platform to enable or disable the new authorization
system for Course Authoring. This flag will be deprecated after 2 Open edX releases, with a DEPR
ticket tracking the deprecation.

A migration process will move existing roles from the legacy implementation to openedx-authz.

A rollback migration process will also be provided to revert from openedx-authz roles back to
legacy roles if the feature flag is disabled. The rollback will only support roles with exact
equivalences between systems; non-equivalent roles will be ignored with warnings logged to the
command output.

Decision
********

* Permissions and roles for course authoring will be initially defined in openedx-authz, following
  the same approach used for Libraries.
* Course authoring permission enforcement using the new system will be optionally enabled via a
  feature flag.
* The feature flag can be enabled instance-wide or for specific courses.
* The feature flag will be deprecated after 2 Open edX releases.
* The deprecation process will remove all legacy code, leaving only the new system.
* During the transition, both systems will coexist, controlled by the feature flag.
* A migration script will migrate legacy permissions to the new system.
* A rollback migration script will revert new permissions to the legacy system.
* The rollback script will only support roles with exact equivalences between systems.
* During rollback, roles that don't exist in the legacy system will be ignored with warnings logged
  to system logs.
* Externalizing roles and permissions definitions will be addressed later after resolving the
  relevant technical debt. This is out of scope for this phase.
* A compatibility layer will be implemented in openedx-platform to support legacy code paths.

Consequences
************

* **Increased System Complexity**: The platform will temporarily operate with two active
  authorization models.
* **Data Duplication**: Permission data will exist in both systems until final cutover, requiring
  synchronization mechanisms or specific query logic.

Migration Strategy for Course Authoring
----------------------------------------

This phase focuses on migrating course authoring permissions while maintaining current
functionality.

* **Migration Script**: Transform existing role assignments into the new authorization model
  without modifying the legacy database.
* **Enforcement Updates**: Modify and verify enforcement points to use the new system with updated
  roles and permissions for courses.
* **Documentation and Communication**:

  * Create a deprecation ticket to inform the community about changes to course roles and
    permissions.
  * Update `OEP-66`_ documentation regarding the new authorization system for course authoring.

Rejected Alternatives
*********************

* **Solving technical debt and implementing externalized roles and permissions**: Out of scope due
  to time constraints.
* **Removing the legacy system immediately**: Increases risk to existing instances if unexpected
  issues arise.
* **Not providing a rollback migration script**: Would prevent testing on instances and increase
  the probability of failed upgrades.

References
**********

* `PRD Authz for Course Authoring`_
* `OEP-66`_

.. _OEP-66: https://docs.openedx.org/projects/openedx-proposals/en/latest/best-practices/oep-0066-bp-authorization.html

.. _PRD Authz for Course Authoring: https://openedx.atlassian.net/wiki/spaces/OEPM/pages/5364121605/PRD+AuthZ+for+Course+Authoring

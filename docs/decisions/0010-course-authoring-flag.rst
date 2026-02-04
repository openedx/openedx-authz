0010: AuthZ for Course Authoring - Feature Flag Implementation Details
######################################################################

Status
******

**Draft**

Context
*******

We need to implement the new RBAC functionality for course authoring behind a Waffle flag as a
beta feature for several key reasons:

- Enable incremental development without breaking existing functionality
- Allow large sites to test performance and functionality at small scale before full deployment
- Mitigate risks associated with the Verawood release timeline

The feature flag must support enablement at multiple granularity levels:

- **Course level**: Individual courses
- **Organization level**: All courses within an organization
- **Instance level**: All courses across the entire instance

Detailed implementation research can be found in the
`Authoring Waffle Flag Implementation Spike`_.

Decision
********

**Implementation Approach**

- Implement as a Waffle flag with multi-level support:

  - **Course level**: Using `WaffleFlagCourseOverrideModel`_
  - **Organization level**: Using `WaffleFlagOrgOverrideModel`_
  - **Instance level**: Using standard Waffle Switch

- **Flag Configuration**

  - Flag name: ``authz.enable_course_authoring``
  - Management via Django Admin UI or management command
  - Deprecation scheduled after 2 Open edX releases (after Willow)

**Platform Integration**

- All openedx-platform code related to course authoring must respect the flag state
- Multi-course endpoints must handle both legacy and new AuthZ mechanisms simultaneously
- Bidirectional migration process will be implemented (details in separate ADR)

**Migration Behavior**

When the flag state changes, automatic migration occurs immediately:

- **Flag enabled**: Legacy role assignments migrate to new system and are removed from legacy
  system
- **Flag disabled**: New system role assignments migrate to legacy system and are removed from
  new system

  *Note: Roles without legacy equivalents remain in the new system and are not migrated*


Consequences
************

- Documentation will be created for explaining the feature flag
- Documentation will be created for comparing roles between the legacy and new AuthZ systems
- A DEPR ticket will be created to track the deprecation of the feature flag after Willow

Rejected Alternatives
*********************

**Instance-level only flag implementation**
  Makes testing difficult on large instances with mixed requirements.

**Django setting implementation**
  Requires deployment and service restart for flag changes, increasing testing complexity and risk.

**Per-user level implementation**
  Creates inconsistent permission experiences within the same course. Course staff could
  attempt to set permissions in one system for users operating in another system, resulting
  in ineffective permission changes.

References
**********

* `How to Implement the right toggle type`_
* `Authoring Waffle Flag Implementation Spike`_

.. _How to Implement the right toggle type: https://docs.openedx.org/projects/edx-toggles/en/
   latest/how_to/implement_the_right_toggle_type.html#implementing-the-right-toggle-class
.. _Authoring Waffle Flag Implementation Spike: https://openedx.atlassian.net/wiki/spaces/OEPM/
   pages/5646221313/Spike+-+RBAC+AuthZ+-+Authoring+Waffle+Flag+Implementation
.. _WaffleFlagCourseOverrideModel: https://github.com/openedx/openedx-platform/blob/
   22485757573d32e3c0cb1c36855d83bcd2b1251d/openedx/core/djangoapps/waffle_utils/models.py#L14
.. _WaffleFlagOrgOverrideModel: https://github.com/openedx/openedx-platform/blob/
   22485757573d32e3c0cb1c36855d83bcd2b1251d/openedx/core/djangoapps/waffle_utils/models.py#L75


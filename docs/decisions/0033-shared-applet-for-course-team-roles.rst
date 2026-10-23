0033: Shared Applet for Course-Team Roles
#########################################

Status
******

**Draft**

Context
*******

`ADR 0032`_ places a role in the applet for the bounded context where it is assigned, while roles that cut across several contexts need a specific decision about where they live. The course-team roles are the first case, since they are assigned to members of a course team and combine permissions from course authoring, enrollments, grading, and learner administration.

These roles do not all combine permissions in the same way today. ``course_admin`` and ``course_staff`` receive permissions from several applets, ``course_editor`` and ``course_auditor`` receive every permission from ``course_authoring``, and the legacy roles such as ``course_limited_staff`` only list their legacy compatibility permission. However, the `Instructor Dashboard Permissions`_ proposal allows more restricted roles to receive a subset of the dashboard permissions, so the roles that rely on one applet today may combine several later.

Decision
********

The course-team roles are cross-cutting, so they live in the shared ``course_team_roles`` applet regardless of which applets currently provide their permissions. Their base definitions list only the permissions that ``course_team_roles`` owns, such as the legacy compatibility permissions, while every other applet adds the permissions it owns through ``role_extensions``.

Any other group of cross-cutting roles needs its own decision about where it lives.

Consequences
************

1. A course-team role keeps its owner when another applet starts adding permissions to it.
2. Every role that a course team can assign is defined in one place, next to the legacy role equivalences.
3. Base definitions such as ``course_editor`` may list no permissions, so the schema has to accept an empty permission list.

Rejected Alternatives
*********************

**Placing each course-team role in the applet that provides its permissions**
  ``course_editor`` and ``course_auditor`` would move to ``course_authoring``, splitting one group of roles across applets, and each role would have to move again once another applet added permissions to it.

References
**********

* `ADR 0032`_
* `Instructor Dashboard Permissions`_

.. _ADR 0032: 0032-applets-for-built-in-authorization-capabilities.rst
.. _Instructor Dashboard Permissions: https://openedx.atlassian.net/wiki/spaces/OEPM/pages/6789234689/Instructor+Dashboard+Permissions

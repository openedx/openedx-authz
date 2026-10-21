0032: Applets for Built-In Authorization Capabilities
#####################################################

Status
******

**Draft**

Context
*******

`ADR 0005`_ defines ``openedx_authz.api`` as the public API for the reusable authorization framework, although the package also ships the Open edX-specific roles and permissions that the platform uses, as YAML schema files and Python constants. These definitions are grouped by type, so ``authz/schema/course_permissions.yaml`` defines every course permission and ``authz/schema/course_roles.yaml`` lists the complete permissions for each course role.

Grouping by type keeps roles apart from permissions, but it also puts definitions from unrelated responsibilities into the same course-level files, so a reader can see that a permission applies to a course without being able to tell whether enrollments, grading, or another area owns it.

`Issue #484`_ defines permissions for the Instructor Dashboard, which brings together several areas of course administration, including enrollments, the gradebook, learner extensions, and cohorts. The `edX DDD Bounded Contexts`_ map places those areas in different parts of the platform, so adding their permissions to the shared files would mix definitions from several bounded contexts and make those files the place where every new contribution has to be added.

The existing decisions do not say where these definitions belong, because `ADR 0026`_ defines ownership and placement rules only for REST endpoints, while `PR #421`_ raised the same ownership question for constants and schema definitions.

`ADR 0010 in openedx-core`_ answers a similar question for a single Django app by giving each bounded responsibility its own internal package, which it calls an applet. The authorization schema can already support that structure, since `ADR 0019`_ allows a package to load several schema directories and `ADR 0023`_ allows one schema contribution to extend a role defined by another.

Decision
********

We will organize built-in Open edX authorization capabilities as applets under ``openedx_authz.applets``, while the existing public API and import paths remain stable, since ``openedx_authz.constants`` re-exports each applet's constants and the ``authz.schema`` provider lists each applet's schema directory.

1. Applet boundaries
====================

An applet is an internal Python package that gives one bounded responsibility a concrete place inside the existing ``openedx_authz`` Django app and keeps the related YAML definitions, Python constants, REST endpoints, filters, and tests together when those elements exist:

.. code-block:: text

   openedx_authz/applets/
       course_team_roles/
           constants.py
           schema/
       enrollments/
           constants.py
           schema/
       course_authoring/
           constants.py
           schema/
           rest_api/
       ...

The `edX DDD Bounded Contexts`_ map says where each responsibility belongs, but it does not prescribe a package layout inside one Django app, so applets turn those boundaries into Python packages that keep the code and definitions for each responsibility together. Reusable schema handling, enforcement, persistence, and public APIs stay in their existing top-level packages, since every applet depends on them.

Dependencies point in one direction, from clients to the public modules, from those modules to the applets, and from the applets to the shared packages:

.. code-block:: text

   clients, such as openedx-platform
     └── openedx_authz.api, openedx_authz.constants
           └── openedx_authz.applets.<applet>
                 └── openedx_authz.api.data, openedx_authz.data

Applets do not import each other, since role extensions in YAML already connect their definitions. Applets are internal, so clients import constants from ``openedx_authz.constants``, and an applet can change or move without changing client code.

2. Definition ownership
=======================

A permission belongs to the applet responsible for the action or data that the permission controls. For example, the ``enrollments`` applet defines the permissions for viewing or changing enrollments, along with their metadata, constants, and contributions to shared roles, so code elsewhere may check those permissions through the public API while their definitions remain in ``enrollments``.

The `edX DDD Bounded Contexts`_ map guides this choice, especially when a user interface combines several capabilities. To place a new permission, we find the bounded context that owns its action or data in the map and add the permission to that context's applet, or create an applet when the context has none yet. Applet names describe the definitions they hold, so the following table records which bounded context each one stands for:

.. list-table::
   :header-rows: 1

   * - Applet
     - Bounded context
     - Definitions
   * - ``course_authoring``
     - Course Run Authoring and Learning Content Authoring
     - Course authoring and course-team permissions
   * - ``content_libraries``
     - Learning Content Authoring and Learning Content Repository
     - Library roles and permissions
   * - ``enrollments``
     - Content Access / Enrollments
     - Viewing and changing course enrollments
   * - ``learner_grading``
     - Consuming Learning Content
     - The gradebook and grading tools for individual learners
   * - ``learner_administration``
     - Support Learning
     - Course information, learner extensions, and cohorts
   * - ``course_team_roles``
     - Shared by several bounded contexts
     - Roles held by members of a course team
   * - ``role_management``
     - Authorization
     - Admin Console role assignment workflows

3. Course roles
===============

Following these rules, ``course_team_roles`` defines the identifiers and metadata for ``course_admin`` and ``course_staff``, whose base definitions have empty permission lists, and each capability applet then adds the permissions it owns through ``role_extensions``:

.. code-block:: yaml

   # course_team_roles/schema/roles.yaml
   roles:
     - id: course_admin
       display_name: Course Admin
       scopes:
         - course-v1
       permissions: []

   # enrollments/schema/role_extensions.yaml
   role_extensions:
     - role_id: course_admin
       add_permissions:
         - courses.view_enrollments
         - courses.enroll_learners

Schema version 1 will therefore accept an empty permission list, while the compiled roles will still contain the complete permission lists contributed by the applets.

4. REST endpoints
=================

REST endpoints continue to follow the ownership rules in `ADR 0026`_, and applets now give those rules a package boundary. The Admin Console endpoints therefore move to ``role_management``, since they support the same role-management workflow, although this placement does not settle the ownership of the organization data returned by ``AdminConsoleOrgsAPIView``, and ``WaffleFlagStatesAPIView`` moves to ``course_authoring``. In both cases, the existing URLs and route names remain unchanged.

5. Imports
==========

Although applets are internal packages, ``openedx_authz.constants.permissions`` and ``openedx_authz.constants.roles`` continue to export every existing constant, while ``COURSE_ADMIN`` and ``COURSE_STAFF`` continue to contain their complete permission lists, so existing import paths remain valid when code moves into an applet.

YAML remains the source of truth for static definitions, although each applet will maintain its Python constants manually for now, so tests compare those constants with the applet's YAML definitions, and generating them from YAML may replace this process in later work.

6. Future extraction
====================

The applets remain inside ``openedx-authz`` for this work, so implementing the ownership model and the permissions from `Issue #484`_ does not require coordinated changes across the services that use the library, and since their definitions describe the underlying actions and data rather than one user interface, another client can reuse the same permissions when it exposes the same responsibility.

An applet may later move to the service that owns its responsibility and contribute its definitions through the existing ``authz.schema`` entry point, although this decision does not include that extraction because the service boundary, package dependency, and compatibility path for the Python constants would need to be agreed first.

Consequences
************

1. Each built-in definition has an explicit owner based on the capability it protects.
2. Adding a capability does not require adding its definitions to shared course permission and role files.
3. The complete permission list for a course role is assembled from several schema contributions, so readers use the compiled schema or the public role constants to inspect that list.
4. Each permission identifier appears in YAML and Python until generated constants replace the manually maintained files.
5. The Admin Console and course-authoring endpoints move again after `ADR 0026`_, although their public URLs, route names, request and response contracts, and import paths remain stable.
6. Reviewers must identify unwanted dependencies between applets because this decision does not add automated import-boundary checks.
7. Applets create boundaries that can support later extraction, although moving one to another service requires a separate decision about dependencies and compatibility.

Rejected Alternatives
*********************

**Keeping all definitions in the shared files**
  Definitions would remain grouped by type, leaving ownership implicit and continuing the growth of the shared course files.

**One applet for each screen, such as the Instructor Dashboard**
  A permission that Studio and the dashboard both use would have two possible owners.

**A separate Django app for each feature**
  Each feature would gain a separate app label and installation boundary, which the definitions and integrations covered by this decision do not require.

**Moving the definitions to their owning services now**
  This would place the definitions at their eventual service boundary, but it would also require coordinating package dependencies and compatibility imports before implementing the permissions in `Issue #484`_, while the existing schema contribution mechanism leaves that move available after those boundaries are agreed.

References
**********

* `Issue #484`_
* `PR #421`_
* `ADR 0005`_
* `ADR 0010 in openedx-core`_
* `edX DDD Bounded Contexts`_
* `ADR 0019`_
* `ADR 0023`_
* `ADR 0026`_

.. _Issue #484: https://github.com/openedx/openedx-authz/issues/484
.. _PR #421: https://github.com/openedx/openedx-authz/pull/421
.. _ADR 0005: 0005-architecture-and-data-modeling.rst
.. _ADR 0010 in openedx-core: https://github.com/openedx/openedx-core/blob/6a26b3a4181815a44e9d724c16857b61b484b0ea/docs/openedx_content/decisions/0010-merge-authoring-apps-into-openedx-content.rst
.. _edX DDD Bounded Contexts: https://openedx.atlassian.net/wiki/spaces/AC/pages/663224968/edX+DDD+Bounded+Contexts
.. _ADR 0019: 0019-authorization-schema-discovery.rst
.. _ADR 0023: 0023-extend-static-roles.rst
.. _ADR 0026: 0026-rest-api-domain-ownership-boundary.rst

0017: Define Static Roles and Permissions in an Authorization Schema
####################################################################

Status
******

**Draft**

Context
*******

`ADR 0016`_ defines static roles in the authz schema and dynamic roles in the authz model, which the API manages through the Casbin adapter. Today, however, static roles and permissions are spread across Python constants, Python role mappings, ``authz.policy``, and frontend code. A developer who adds a role or permission must therefore update several representations, including a separate copy of its display information in the frontend.

Casbin remains the authorization engine, and its adapter continues to read and write policy rows. The authz schema adds the Open edX format that Casbin does not provide, allowing an application to declare stable identifiers, supported scopes, role permissions, and display information in one place. During deployment, the schema is compiled into Casbin rows, while the API makes the display information available to the frontend.

Decision
********

#. Schema format and boundary
=============================

The authz schema is a versioned YAML format for static permissions, permission categories, roles, and changes to existing roles. Every file declares ``schema_version`` and ``priority``. Open edX publishes a YAML Schema for this format so that editors, CI, and the compiler all apply the same field and validation rules.

The existing static role and permission definitions in Python modules and ``authz.policy`` will move into the schema. Once this migration is complete, the schema becomes the source for static definitions, so developers add a new role or permission there without duplicating it in Python constants or policy files.

#. Permissions and categories
=============================

A permission contains:

* ``namespace`` and ``name``, which form the stable identifier used by application checks, such as ``courses.view_course``;
* the scope namespaces where it can apply;
* a normalized permission category; and
* ``display_name``, ``description``, and an optional Paragon icon name.

For example:

.. code-block:: yaml

   permission_categories:
     - id: course_content
       display_name: Course content
       description: Permissions for viewing and editing course content.
       icon: Article

   permissions:
     - namespace: courses
       name: view_course
       display_name: View course
       description: View course configuration and content.
       category: course_content
       scopes: [course-v1]
       icon: Visibility
     - namespace: courses
       name: delete_course
       display_name: Delete course
       description: Delete a course.
       category: course_content
       scopes: [course-v1]
       icon: Delete

Here, ``course_content`` groups the two permissions for display. The complete permission IDs are ``courses.view_course`` and ``courses.delete_course``, while ``course-v1`` is the scope namespace where they apply. Application code uses the complete permission ID, so changing ``display_name`` does not change permission checks.

#. Roles and role extensions
============================

A role contains a stable identifier, display name, description, supported scope namespaces, and a list of complete permission identifiers. When an application needs to change an existing role, it uses ``role_extensions``. An extension may add or remove permissions and may replace the role's display name or description.

Version 1 does not define display order for roles, permissions, or categories. Clients may sort them alphabetically or apply another order that suits their interface.

.. code-block:: yaml

   schema_version: "1.0"
   priority: 100

   roles:
     - id: course_observer
       display_name: Course observer
       description: Can review a course without changing it.
       scopes: [course-v1]
       permissions:
         - courses.view_course

   role_extensions:
     - role: course_admin
       add_permissions:
         - courses.delete_course

In these examples, ``courses.view_course`` appears under ``course_content`` in the UI and belongs to the new ``course_observer`` role. The ``role_extensions`` entry adds ``courses.delete_course`` to the existing ``course_admin`` role. The compiler can render the observer's role-permission relationship as:

.. code-block:: text

   p, role^course_observer, act^courses.view_course, course-v1^*, allow

The compiler also creates a row that links ``course_admin`` to ``courses.delete_course``. Priority resolves conflicts between definitions and role extensions; it does not control how roles or permissions appear in the UI.

The schema contains static definitions, while user assignments and user-defined roles stay in the application database. Casbin's ``model.conf`` and matcher also remain owned by ``openedx-authz``.

#. Validation and conflicts
===========================

Validation first checks each file against the published schema. It rejects:

* invalid YAML, unknown fields, missing required fields, and values with the wrong type;
* unsupported schema versions;
* IDs that contain uppercase letters or unsupported punctuation;
* icon names that don't follow the available icons from ``@openedx/paragon/icons``; and
* display fields that exceed the agreed size limits.

After loading every file, validation checks the combined definitions. It rejects:

* references to permissions or categories that do not exist;
* a role extension whose role does not exist in the combined definitions;
* a role used in a scope where one of its permissions cannot apply;
* conflicting definitions or role extensions with the same priority; and
* unsupported combinations of schema versions.

The validator warns about duplicate definitions, including identical definitions, and about definitions or role extensions that do not take effect because another file has a higher priority. The highest-priority contribution resolves a conflict. If several files add the same permission to the same role, the compiler creates one Casbin row and records each contributing source.

Unit tests can load schema fixtures into an in-memory Casbin enforcer and check allowed and denied requests. This follows the model-testing approach used by OpenFGA and the schema assertions used by SpiceDB, while keeping the tests in normal application test suites.

Consequences
************

* Applications declare static permission identifiers, role-to-permission assignments, and UI fields in the same YAML format.
* Application checks continue to use stable permission identifiers and do not depend on role names.
* Application clients can read the compiled definitions from the API and remove its copy.
* Schema validation needs both per-file checks and checks across all files, including conflicts and role extensions.
* Role extensions can change the permissions assigned to built-in roles. Deployment must report them clearly, and the operator remains responsible for approving them.
* Version 1 excludes permission implication and role inheritance.

Rejected Alternatives
*********************

Raw Casbin policy files
=======================

They express the rows Casbin needs for permission checks but omit the display fields and source information required by users and applications.

Python constants and role mappings
==================================

Definitions would remain split across backend and frontend code. Applications would also need to change ``openedx-authz`` to add definitions they own.

Embedded categories on every permission
=======================================

Repeating category labels makes localization and consistent presentation harder. A normalized category gives permissions one stable grouping reference.

References
**********

* `ADR 0016`_
* `Casbin adapters`_
* `ASDF YAML Schema`_
* `Paragon icons`_

.. _ADR 0016: 0016-static-and-dynamic-roles.rst
.. _Casbin adapters: https://v3.casbin.org/docs/adapters
.. _ASDF YAML Schema: https://www.asdf-format.org/projects/asdf-standard/en/1.0.2/schemas/yaml_schema.html
.. _Paragon icons: https://paragon-openedx.netlify.app/components/icon/

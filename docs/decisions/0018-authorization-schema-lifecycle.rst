0018: Define the Authorization Schema Lifecycle
###############################################

Status
******

**Draft**

Context
*******

During deployment, the authz tooling reads the schema files, creates the Casbin rows, and stores the result. Casbin then uses those rows for permission checks, while the API returns the stored definitions that describe the available roles and permissions. The lifecycle terms below explain this process and identify when the database changes.

The loader of the schema also needs to account for data that is already in the Casbin adapter tables, such as static policy rows, user-defined roles, and user assignments. A deployment must preserve the data it does not own, and running the same deployment more than once must produce the same result.

Decision
********

#. Lifecycle vocabulary
=======================

The authz schema lifecycle uses these terms:

* **discover** finds static schema resources contributed by applications;
* **load** reads those resources into schema documents;
* **validate** checks each document and the complete set of static definitions;
* **compile** resolves references, extensions, and priority conflicts into one set of static definitions;
* **render** creates Casbin policy rows from the compiled definitions without changing the database;
* **apply** stores the compiled definitions, their sources, and the rows while preserving dynamic roles and assignments; and
* **consume** uses the resulting policy for permission checks and exposes the stored definitions through APIs.

The following example shows how one file moves through the lifecycle:

1. **Discover** finds ``course_authoring/authz/course_roles.authz.yaml``, and **load** parses it as an authz schema file.
2. **Validate** checks the fields in the file and confirms that its references exist.
3. **Compile** combines its ``course_admin`` extension with the original role definition.
4. **Render** creates the Casbin ``p`` row for the added permission, but does not write it to the database.
5. **Apply** writes the row, the compiled definition, and its source information to the database.
6. **Consume** begins after Casbin reloads the policy and the API can return the updated role.

#. Deployment-time compilation
==============================

Before the application starts serving traffic, deployment completes every step from discover through apply. Permission checks can then use the stored policy without compiling the schema again.

Together, the schema documents define the static roles and permissions that should exist. Applying the same documents again leaves those rows unchanged, preserves user assignments and user-defined roles, and does not create duplicates or modify unrelated policy.

For example, if deployment runs twice with the same ``course_observer`` definition, the database still contains one role-permission row and the second run reports that the policy is unchanged.

#. Storage ownership
====================

Each part of the system updates the records it owns. The schema loader manages generated static rows and their source information, the dynamic role API manages roles created by administrators, and the role-assignment API manages user assignments.

For example, the loader may update the static row that links ``courses.view_course`` to ``course_observer``, but it must preserve the assignment that gives Alice that role in ``course-v1:OpenedX+DemoX+DemoCourse`` as well as any dynamic roles created by an administrator.

#. Role identifier conflicts
============================

Static and dynamic roles share the same set of names, so neither kind can reuse a name that already exists. The dynamic role API rejects a name used by a static role, and deployment stops when a new static role conflicts with an existing dynamic role.

For example, an administrator cannot create a dynamic ``course_observer`` role when an application already defines a static role with that name. If the dynamic role existed first, a deployment that introduces the static role stops and reports both the contributing package and the conflicting database record, leaving both definitions unchanged.

#. Apply related changes together
=================================

Validation and rendering finish before the database changes. Once they succeed, the loader updates the generated policy, compiled definitions, and source information in one operation; if that operation fails, Casbin continues to use the last working version.

#. Change report and removed roles
==================================

Before writing to the database, the compiler reports the categories, permissions, roles, and role-permission relationships that will change, including changes caused by a higher-priority contribution. Validation errors and failed tests stop deployment before the database changes.

Removing a static role also removes its role-permission relationships. If users still have that role, deployment stops and reports the assignments that must be removed or moved to another role. For example, ``course_observer`` cannot be removed while Alice still has that role.

#. Administrative fallback
==========================

Application and plugin code cannot edit generated static rows directly. During an incident, however, an administrator may use the Django admin, which records who changed what and why, and explains whether the next schema deployment will replace the change.

Consequences
************

* Deployment compiles the schema before the application begins serving requests for reliability and performance.
* Repeating a deployment creates no duplicate rows and preserves data owned by runtime services.
* The schema loader, dynamic role API, and assignment API can update only the rows they own.
* Role identifier conflicts are reported before either definition is changed.
* Applying a schema requires a database transaction or another mechanism that updates all generated rows together.
* Operators receive the change report before the database is updated.
* An assignment to a role being removed blocks deployment and preserves the current access.

References
**********

* `ADR 0016`_
* `ADR 0017`_

.. _ADR 0016: 0016-static-and-dynamic-roles.rst
.. _ADR 0017: 0017-static-authorization-schema.rst

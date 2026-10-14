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

1. Lifecycle vocabulary
=======================

The authz schema lifecycle has seven phases:

1. **Discover** identifies the static schema resources contributed by installed applications. Its output is the set of resources that the deployment will process, together with enough source information to identify each contribution.
2. **Load** reads the discovered resources and parses them into schema documents. This phase turns files into data that later phases can inspect, but it does not decide how contributions relate to each other.
3. **Validate** checks each document and the complete set of contributed definitions. It rejects input that cannot form a valid authorization schema before any persistence-ready records are produced or stored.
4. **Compile** resolves references, extensions, and priority conflicts across the validated documents. Its output is one compiled authorization definition that represents the contributions selected for this deployment.
5. **Render** translates the compiled definition into the records required by the persistence layer. It determines what would be stored without changing the database, which allows the complete result to be checked and reported first.
6. **Apply** stores the compiled definition, its source information, and the rendered records in one operation. It changes only schema-managed data and preserves dynamic roles and user assignments.
7. **Consume** uses the stored result. Casbin uses the generated policy for permission checks, while APIs use the stored definitions to describe the available roles and permissions.

The following example shows how an application contribution moves through the lifecycle:

1. **Discover** finds ``course_authoring/authz/schema/roles.yaml``, which contains an extension that adds a permission to ``course_admin``.
2. **Load** parses the resource into a schema document.
3. **Validate** checks the document and its place in the complete schema.
4. **Compile** resolves the extension against the original ``course_admin`` definition.
5. **Render** prepares the records for the resulting role-permission relationship.
6. **Apply** stores those records with the compiled definition and source information.
7. **Consume** begins once Casbin can use the updated policy and the API can return the updated role.

These definitions establish the purpose and boundary of each phase. Their implementation details may require separate ADRs as the phases are built.

2. Deployment-time compilation
==============================

Before the application starts serving traffic, deployment completes every step from discover through apply. Permission checks can then use the stored policy without compiling the schema again.

Together, the schema documents define the static roles and permissions that should exist. Applying the same documents again leaves those rows unchanged, preserves user assignments and user-defined roles, and does not create duplicates or modify unrelated policy.

For example, if deployment runs twice with the same ``course_observer`` definition, the database still contains one role-permission row and the second run reports that the policy is unchanged.

3. Storage ownership
====================

Each part of the system updates the records it owns. The schema loader manages generated static rows and their source information, the dynamic role API manages roles created by administrators, and the role-assignment API manages user assignments.

For example, the loader may update the static row that links ``courses.view_course`` to ``course_observer``, but it must preserve the assignment that gives Alice that role in ``course-v1:OpenedX+DemoX+DemoCourse`` as well as any dynamic roles created by an administrator.

4. Role identifier conflicts
============================

Static and dynamic roles share the same set of names, so neither kind can reuse a name that already exists. The dynamic role API rejects a name used by a static role, and deployment stops when a new static role conflicts with an existing dynamic role.

Because this ADR covers the lifecycle of static definitions, it establishes that static role IDs follow the conventions in the :ref:`Authorization Schema Reference`. Naming conventions for dynamic roles are outside its scope.

For example, an administrator cannot create a dynamic ``course_observer`` role when an application already defines a static role with that name. If the dynamic role existed first, a deployment that introduces the static role stops and reports both the contributing package and the conflicting database record, leaving both definitions unchanged.

5. Apply related changes together
=================================

Validation and rendering finish before the database changes. Once they succeed, the loader updates the generated policy, compiled definitions, and source information in one operation; if that operation fails, Casbin continues to use the last working version.

6. Change report and removed roles
==================================

Before writing to the database, the compiler reports the categories, permissions, roles, and role-permission relationships that will change, including changes caused by a higher-priority contribution. Validation errors and failed tests stop deployment before the database changes.

At deployment time, the compiler compares the newly compiled definitions with the stored definitions and their source records to identify these changes. This ADR does not prescribe how that comparison is implemented.

Removing a static role also removes its role-permission relationships. If users still have that role, deployment stops and reports the assignments that must be removed or moved to another role. For example, ``course_observer`` cannot be removed while Alice still has that role.

An explicit force option allows an operator to remove the role and its remaining assignments together. Without that option, deployment stops when assignments still exist.

7. Administrative fallback
==========================

Application and plugin code cannot edit generated static rows directly. During an incident, however, an administrator may use the Django admin, which records who changed what and why, and explains whether the next schema deployment will replace the change.

8. Serialize concurrent applies
===============================

Section 5 keeps the writes of a single apply atomic. This section covers what happens when two applies run at the same time — for example two deployments racing, or a deployment overlapping an administrative re-run.

Apply is a read-modify-write cycle: it reads the current policy and definitions, computes the difference against the compiled schema, then writes the generated policy and the definition records. Two applies that run concurrently can each read the same starting state, each compute a difference against it, and then both write. The result is a lost update in which the generated policy and the definition records disagree — for instance the definitions retain a permission that the policy no longer grants — even though each apply individually did an atomic write.

An apply therefore runs under a lock that lets only one apply proceed at a time. A second apply waits until the first finishes and then reads the state the first committed, so its difference is computed against current data rather than a stale snapshot. The lock is released automatically when the apply's transaction ends — on success, failure, or a lost connection — so a failed or interrupted apply cannot leave the lock held.

Taking the lock is not sufficient on its own; the apply must also read current data once it holds the lock. Two things make that true. First, the apply reads committed database state under the lock rather than a snapshot captured before the lock was granted, because some databases fix a transaction's read view at its first read. Second, the apply refreshes any in-memory copy of the policy it keeps, so the difference is computed from what the database actually holds and not from a cached view a previous apply left behind.

The signal that tells running services their cached policy is stale is updated inside the same transaction as the policy writes. If that signal were updated after the transaction, the new policy would be committed and visible while the signal still indicated the old version, and a service could serve the superseded policy for that window. Updating the signal together with the writes closes that window: a service either sees both the new policy and the new signal, or neither.

This ADR records the decision to serialize applies and to read current state under the lock. It does not prescribe the specific locking primitive, isolation level, or signalling mechanism; those are implementation choices that depend on the deployment's database.

Two limitations are accepted:

* **Single-database assumption.** Serialization holds only when the generated policy and the lock live in the same database. The engine already assumes one database for its policy storage, so this is consistent with the rest of the system.
* **Blocking wait without observability.** A second apply waits for the first with no timeout and no distinct signal, so a blocked apply is operationally indistinguishable from a slow one. This is acceptable because apply runs at deployment time, not on the request path.

Consequences
************

* Deployment compiles the schema before the application begins serving requests for reliability and performance.
* Repeating a deployment creates no duplicate rows and preserves data owned by runtime services.
* The schema loader, dynamic role API, and assignment API can update only the rows they own.
* Role identifier conflicts are reported before either definition is changed.
* Applying a schema requires a database transaction or another mechanism that updates all generated rows together.
* Operators receive the change report before the database is updated.
* An assignment to a role being removed blocks deployment unless an operator explicitly removes the role and its assignments together.
* Concurrent applies are serialized so they cannot interleave into a lost update, and each apply reads current committed state under the lock and updates the cache-staleness signal together with its writes.

References
**********

* `ADR 0016`_
* `ADR 0017`_

.. _ADR 0016: 0016-static-and-dynamic-roles.rst
.. _ADR 0017: 0017-static-authorization-schema.rst

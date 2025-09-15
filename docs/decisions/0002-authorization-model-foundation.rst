0002: Authorization (AuthZ) Model Foundations
#############################################

Status
******
**Draft**

Context
*******
Open edX needs a single way to decide: who can do what, on which resource, and under which conditions. Today, permissions are checked in many different ways. Some systems are feature-specific (``student_courseaccessrole``, ``django_comment_client_role``, ``contentlibrarypermission``). Others use global roles passed in JWTs. Many checks are written directly in code (``if user.is_superuser``). This makes the system hard to extend, hard to change, and not easy to audit.

We want an authorization model that:

* Uses a clear and consistent vocabulary throughout.
* Explicitly supports industry standards and is built on battle-tested technologies.
* Is flexible but still simple to maintain.
* Can explain every decision (the system should be transparent on why access was granted or not).
* Enforces decisions in a unified and centralized way, rather than ad-hoc implementations for immediate needs.
* Supports query-based access patterns out of the box.
* Focuses on connecting stakeholders and making policies clear and accessible to everyone involved.

.. note::

   Authorization is considered independent from authentication. There will be an interface between them so we can combine correctness and consistency. A separate ADR will cover the details of this interface (e.g., how roles in JWTs are handled and how checks are made).

Decision
********

I. Canonical Permission Model
=============================

Normalize all checks to Subject-Action-Object-Context (S-A-O-C)
---------------------------------------------------------------
* We express authorization as: is **Subject** allowed to do **Action** on **Object** under **Context**?
* This normalization is used in policies, code, queries, and audits.
* Examples:

  - Can Alice (subject) edit (action) the course ``course-v1:OpenedX+DemoX+DemoCourse`` (object) as part of Org A (context)?
  - Can Bob (subject) read (action) the library ``lib:DemoX:CSPROB`` (object)?

II. Resources and Scopes
========================

Scopes as first-class citizens in permission-granting
-----------------------------------------------------
* A **scope** defines the boundary within which a role or policy applies (for example: platform-wide, organization-wide, a single course, or a specific library).
* Treating scopes as **first-class citizens** means they are explicitly modeled in the system, not hidden inside ad-hoc resource definitions. They must be available to policies, queries, and audits in a consistent way.
* Scopes can be **parameterized** (e.g., ``organization:ORG-A``, ``course:course-v1:OpenedX+DemoX+DemoCourse``,  ``site:sandbox.openedx.org``, ``instance``) to support granular checks.
* **Inheritance across scopes** must be supported (e.g., permissions granted at the organization level can cascade to courses in that organization when intended).
* By making scopes explicit and consistent, we avoid the fragmentation seen in legacy systems (different services using different implicit notions of "instance", "org", "course").
* Scope is part of the **Context** in S-A-O-C checks.

III. Authorization Paradigm
===========================

Adopt ABAC as the goal; Scoped RBAC as a first step
---------------------------------------------------
* We recommend **ABAC** as the main model for Open edX authorization.
* **Scoped RBAC** may be used pragmatically as a first step, with the ambition of moving into a more granular system with ABAC.
* **RBAC** handles role-based permissions well (e.g., "admins can edit any record").
* **ABAC** adds finer control by using attributes of subjects, resources, and context (e.g., "editors can edit only in their assigned organizations or locations").
* **ReBAC** is not chosen because it adds complexity and we do not have strong use cases today.

  - Although ReBAC solves interesting problems out of the box (inheritance, recursive relationships), it introduces a mental shift in how to think about authorization so we're not explicitly adopting it for now.
  - Some technologies are ReBAC-first but can also implement RBAC and ABAC effectively. These are not excluded, but they shouldn't go against our **simplicity principle**.

* **Simplicity principle**: avoid adding features like deep role inheritance or complex hierarchies until there are clear use cases that require them.

IV. Policy Definition
=====================

Externalize policies
--------------------
* Policies must be defined and managed externally (e.g., in policy files or a database store), not embedded directly in application logic. The default model is an allowlist: actions are permitted only when explicitly granted.

  - Prefer declarative policy definitions (e.g., JSON, YAML, policy language) over in-code checks like ``if user.is_superuser``.
  - Prefer explicit permission checks over implicit role lookups in business logic.

* Policies must explicitly show whether access comes from:

  - **Default roles** (out-of-the-box), or
  - **Extensions** (plugin-based).

* Policies must be versioned, reviewable, and easy to share.
* If policies are not easy to read, provide an abstracted or friendly view.
* Show the **effect** of policies when available (allow/deny).

V. Enforcement
==============

Use centralized enforcement
---------------------------
* Authorization checks must go through a single path, not spread across ad-hoc implementations.
* Centralized enforcement can take two possible forms:

  - A **central service** that acts as the decision point for all checks.
  - A **shared adapter/library** that is the only way services can ask for permissions.

* In both cases, services must not embed authorization logic directly.

VI. Engines and Integration
===========================

Use proven frameworks with ABAC support and an adapter
------------------------------------------------------
* Use existing open source frameworks (`Casbin <https://casbin.org>`_, `Cerbos <https://www.cerbos.dev>`_, `OpenFGA <https://authzed.com/spicedb>`_, `SpiceDB <https://spicedb.dev>`_, `Ory Keto <https://www.ory.sh/keto>`_, etc.).
* Recommend against building a custom engine since authorization is a well-established domain with many existing solutions, reinventing the wheel introduces unnecessary complexity and maintenance burden.
* The chosen technology must:

  - Support **ABAC** to allow growth beyond role-only systems.
  - Provide **explicit and clear permission checks** in code, similar in clarity to Django's ``user.has_perm``.
  - Avoid introducing obscure or confusing query styles.

* Provide an **adapter layer** that:

  - Translates Open edX concepts into the engine model.
  - Keeps Open edX services engine-agnostic.
  - Ensures consistent logging and decision tracing.

VII. Extensibility
==================

Make roles, permissions, and resources pluggable
------------------------------------------------
* Extensibility should include:

  - Adding **custom roles** that can be composed from or unioned with existing permissions.
  - Adding **new permissions (verbs)** that build on top of existing ones.
  - Defining **new resources** (e.g., "assignment") and expressing their relations to existing ones (e.g., platform → organization → course).

* Applications must keep calling the same consistent check (e.g., *can(subject, action, object)*), while the schema or policy evolves underneath.

VIII. Auditability
==================

Make all decisions explainable
------------------------------
* Every decision must have a trace:

  - Which policy was used.
  - Which attributes were checked.
  - The effect (allow/deny).

* Logs must let admins ask: "Why was this action allowed or denied?"
* Traces must capture runtime values so audits remain possible later.
* Permission checks in code must be **explicit and self-documenting**, so developers and stakeholders can easily understand how authorization is asked for in the system.

IX. Security
============

Protect policies and logs against tampering
--------------------------------------------

* The system must guarantee the integrity of authorization policies and decision logs.
* Policies and logs should be stored or managed in a way that makes tampering detectable.

Consequences
************
1. **Strong audit needs.** We must build a central log of all decisions, including attributes and matched policies.
2. **Attribute management.** ABAC requires attributes to be available and normalized. We must also capture their values in logs.
3. **Scoped RBAC transition.** Some parts may use RBAC first, but the chosen system must support full ABAC.
4. **Readable policies.** Even if technical, policies must be presented in a way non-technical people can review.
5. **Scope consistency.** The system must provide a consistent definition and handling of scopes and resource hierarchies across all services, so that policies and checks have the same meaning everywhere.
6. **Performance impact.** Logging and attributes add overhead. We must design caching and retention strategies.
7. **Migration work.** Old in-code checks must be replaced step by step with policies.
8. **Querying system.** The authorization model must support query-style checks (e.g., "list all objects this user can edit") at least as well as the current bridgekeeper system, either by integration or by providing equivalent functionality.

Rejected Alternatives
*********************
* **RBAC-only**: too limited for contextual decisions.
* **ReBAC**: rejected because it adds complexity and we lack strong use cases today.
  - While ReBAC solves inheritance and recursive relationships well, it introduces complexity and a different way of thinking about authorization.
* **In-code checks**: not auditable or shareable.
* **Custom-built engine**: unnecessary when proven frameworks exist.

References
**********
- `AuthZ Key Concepts <https://openedx.atlassian.net/wiki/spaces/OEPM/pages/5177999395>`_
- `AuthZ Architecture Approach <https://openedx.atlassian.net/wiki/spaces/OEPM/pages/5176229910>`_
- `PRD Roles and Permissions <https://openedx.atlassian.net/wiki/spaces/OEPM/pages/4724490259>`_

Glossary
********

* **Action**: The operation attempted on a resource (e.g., view, edit, delete).
* **Attribute**: Property of a user or resource used in ABAC (e.g., user.profile.department == course.org).
* **Authorization check**: The explicit way a service asks whether an operation is allowed, always expressed in S-A-O-C form.
* **Authorization models**: Frameworks or approaches that define how to express who can do what, on which resource, and under which conditions. Common models include RBAC, ABAC, and ReBAC.

  * **RBAC (Role-Based Access Control)**: Authorization model where access is granted based on roles assigned to users.
  * **Scoped RBAC**: A variant of RBAC where roles apply within a specific scope (e.g., organization, course, library).
  * **ABAC (Attribute-Based Access Control)**: Authorization model where access is granted based on attributes of the subject, object, and context (e.g., user's organization, resource type, time of day).
  * **ReBAC (Relationship-Based Access Control)**: Authorization model where access decisions are based on explicit relationships between subjects and objects, often modeled as a graph.

* **Permission**: Atomic unit of access (e.g., ``CREATE_COURSE``, ``EDIT_ROLE``).
* **Policy**: A declarative rule that defines which subjects can perform which actions on which objects under which context. Policies are stored outside of code, versioned, and auditable.
* **Relationship**: Link between entities granting access in ReBAC (e.g., user:alice#editor@course:math101).
* **Resource**: The object being accessed (e.g., Course).
* **Role**: A collection of permissions assigned to a user (e.g., Instructor).
* **S-A-O-C (Subject-Action-Object-Context)**: The canonical shape of any authorization check: *is Subject allowed to perform Action on Object under Context?*
* **Scope**: The boundary where a role applies (e.g., Instructor in Course A, Admin in Org B).

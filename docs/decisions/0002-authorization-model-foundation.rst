0002: Authorization (AuthZ) Model Foundations
#############################################

Status
******
**Draft**

Context
*******
Open edX needs a single way to decide: who can do what, on which resource, and under which conditions. Today, permissions are checked in many different ways. Some systems are feature-specific (``student_courseaccessrole``, ``django_comment_client_role``, ``contentlibrarypermission``). Others use global roles passed in JWTs. Many checks are written directly in code (``if user.is_superuser``). This makes the system hard to extend, hard to change, and not easy to audit.

We want an authorization model that is:

* Clear and consistent vocabulary everywhere.
* Explicitly supports industry standards and is built on battle-tested technologies.
* Flexible but still simple to maintain.
* Able to explain every decision (the system should be transparent on why access was granted or not).
* Unified and centralized enforcement rather than ad-hoc implementations for immediate needs.
* Able to support query-based access patterns out of the box.
* Focused on connecting stakeholders and making policies clear and accessible to everyone involved.

.. note::

   Authorization is considered independent from authentication. There will be an interface between them so we can combine correctness and consistency. A separate ADR will cover the details of this interface (e.g., how roles in JWTs are handled and how checks are made).

Decision
********

I. Canonical Permission Model
=============================

Normalize all checks to Subject-Action-Object-Context (S-A-O-C)
----------------------------------------------------------------
* We express authorization as: is **Subject** allowed to do **Action** on **Object** under **Context**?
* This normalization is used in policies, code, queries, and audits.
* Examples:

  - Can Alice (subject) edit (action) Course 123 (object) as part of Org A (context)?
  - Can Bob (subject) read (action) Library X (object)?

II. Resources and Scopes
========================

Scopes as first-class citizens in permission-granting
-----------------------------------------------------
* A **scope** defines the boundary within which a role or policy applies (for example: platform-wide, organization-wide, a single course, or a specific library).
* Treating scopes as **first-class citizens** means they are explicitly modeled in the system, not hidden inside ad-hoc resource definitions. They must be available to policies, queries, and audits in a consistent way.
* Scopes can be **parameterized** (e.g., ``organization:ORG-A``, ``course:CS101``,  ``site:sandbox.openedx.org``, ``instance``) to support granular checks.
* **Inheritance across scopes** must be supported (e.g., permissions granted at the organization level can cascade to courses in that organization when intended).
* By making scopes explicit and consistent, we avoid the fragmentation seen in legacy systems (different services using different implicit notions of "site", "org", "course").

III. Authorization Paradigm
===========================

Adopt ABAC as the goal; Scoped RBAC as a first step
---------------------------------------------------
* We recommend **ABAC** as the main model for Open edX authorization.
* **Scoped RBAC** may be used pragmatically as a first step, with the ambition of moving into a more granular system with ABAC.
* **RBAC** handles role-based permissions well (e.g., "admins can edit any record").
* **ABAC** adds finer control by using attributes of subjects, resources, and context (e.g., "editors can edit only in their assigned organizations or locations").
* **ReBAC** is not chosen because it adds complexity and we do not have strong use cases today.

  - Although ReBAC solves interesting problems out of the box (inheritance, recursive relationships), it introduces a mental shift in how to think about authorization.
  - Some technologies are ReBAC-first but can also implement RBAC and ABAC effectively. These are not excluded, but they shouldn't go against our **simplicity principle**.

* **Simplicity principle**: avoid adding features like deep role inheritance or complex hierarchies until there are clear use cases that require them.

IV. Policy Definition
=====================

Externalize policies
--------------------
* Policies must be defined outside code, not hardcoded with conditionals.

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
============================

Use proven frameworks with ABAC support and an adapter
------------------------------------------------------
* Use existing open source frameworks (Casbin, Cerbos, OpenFGA, SpiceDB).
* Do not build a custom engine.
* The chosen technology must:

  - Support **ABAC** to allow growth beyond role-only systems.
  - Provide **explicit and clear permission checks** in code, similar in clarity to Django's ``user.has_perm``.
  - Avoid introducing obscure or confusing query styles.

* Provide an **adapter layer** that:

  - Translates Open edX concepts into the engine model.
  - Keeps Open edX services engine-agnostic.
  - Ensures consistent logging and decision tracing.

VII. Extensibility
===================

Make roles, permissions, and models pluggable
---------------------------------------------
* Extensibility should include:

  - Adding **custom roles** that can be composed from or unioned with existing permissions.
  - Adding **new permissions (verbs)** that build on top of existing ones.
  - Defining **new models/resources** (e.g., "workspace", "assignment") and expressing their relations to existing ones (e.g., platform → organization → course).

* Applications must keep calling the same consistent check (e.g., *can(subject, action, object)*), while the schema or policy evolves underneath.

VIII. Auditability
=================

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
WIP

Glossary
********
* **Policy**: A declarative rule that defines which subjects can perform which actions on which objects under which context. Policies are stored outside of code, versioned, and auditable.

* **RBAC (Role-Based Access Control)**: Authorization model where access is granted based on roles assigned to users.

* **Scoped RBAC**: A variant of RBAC where roles apply within a specific scope (e.g., organization, course, library).

* **ABAC (Attribute-Based Access Control)**: Authorization model where access is granted based on attributes of the subject, object, and context (e.g., user's organization, resource type, time of day).

* **ReBAC (Relationship-Based Access Control)**: Authorization model where access decisions are based on explicit relationships between subjects and objects, often modeled as a graph.

* **S-A-O-C (Subject-Action-Object-Context)**: The canonical shape of any authorization check: *is Subject allowed to perform Action on Object under Context?*

* **Authorization check**: The explicit way a service asks whether an operation is allowed, always expressed in S-A-O-C form.

* **Query check**: A pattern where the system returns all objects of type X on which a subject can perform a given action, under a given context.

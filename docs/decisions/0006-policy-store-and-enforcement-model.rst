0005: Policy Store and Casbin Configuration Model
#################################################

Status
******
**Draft**

Context
*******

This ADR details how authorization policies are stored, versioned, and configured across the platform. It defines the Policy Store as the single source of truth, describes the relational database schema and metadata, and establishes naming conventions for subjects, actions, objects, and contexts. It also specifies the Casbin ``model.conf`` configuration, including the default matcher, allow/deny effects, static vs. dynamic policies, versioning rules, and how services ship and manage their ``authz.policy`` files.

Decision
********

#. Authorization Engine Configuration
=====================================

Use a Casbin Model CONF that Supports Core Principles
-----------------------------------------------------
- Use a Casbin configuration model (``model.conf``) that supports Subject-Action-Object-Context checks, explicit scopes, and both RBAC and ABAC features.
- Start supporting RBAC with roles and permissions, and evolve towards ABAC as needed to enable more granular and context-aware policies.
- The ``model.conf`` file will be shared across all services unless explicitly overridden for a specific service.
- The model configuration will be versioned and managed as part of the Open edX ecosystem to ensure consistency and traceability.
- Favor simple matchers to improve performance and maintainability. This means avoiding complex regexes and nested logic where possible.
- Explicitly define the effects of policies (allow/deny) and ensure that the default behavior is to deny unless explicitly allowed.
- Use Casbin's built-in support for role hierarchies (g, g2) to manage role inheritance and simplify policy definitions.

Use ``authz.policy`` Files for Default Policies
-----------------------------------------------
- Each service will ship with an ``authz.policy`` file that defines its default policies.
- The ``authz.policy`` file will be loaded by the Open edX Layer at service initialization and saved in the policy store upon first load. They provide a baseline set of policies that ensure consistent behavior across deployments.
- Default policies are immutable after load and provide a baseline set of policies that ensure consistent behavior across deployments.
- Default policies should be subjected to load-testing to ensure they do not introduce performance regressions.

Use a simplicity and clarity-first approach to Policy Definitions
-----------------------------------------------------------------
- Favor the use of simple and easy to read matchers and policies to keep the system maintainable. Revisit complexity if needed.
- Define clear and consistent naming conventions for subjects, actions, objects, and contexts to ensure uniformity across services:
  - Use namespaces to properly identify the subject, action, object, and context. For example, use ``org:123`` to refer to a specific org with ID 123. The exceptions for this rule are the objects that already have a namespace like ``course-v1:OpenedX+DemoX+DemoCourse`` or ``lib:DemoX:CSPROB``.
  - Use singular verbs for actions (e.g., ``view``, ``edit``, ``delete``) with snake_case formatting when multiple words are needed (e.g., ``view_grades``, ``edit_content``).
  - Use the username as the subject when referring to individual users (e.g., ``alice``, ``bob``).
  - Use clear and descriptive names for roles. (e.g., ``course_admin``, ``content_creator``).
- Use custom matchers to implement complex logic, but keep them as simple and reusable as possible.
- Document all default policies with in-line comments in the ``authz.policy`` files to explain their purpose and usage.

Roles are scoped to a specific context in the policy
----------------------------------------------------
- Grouping resources will not be implemented via Casbin's built-in role hierarchies (g, g2) but will be explicitly managed when checking permissions in the application layer. For example, if a user has the ``course_admin`` role in ``org:123``, this will not automatically grant them the ``course_admin`` role in all courses within that org. Instead, the application layer will need to check both the user's role and the specific context (e.g., organization or course) when making authorization decisions.
- Define roles that are context-specific, such as ``course_admin`` for a specific course or ``org_admin`` for a specific organization.

#. Policy Management and Versioning
====================================

Differentiate Between Static and Dynamic Policies
-------------------------------------------------
- Consider two types of policies: static policies (shipped with services in ``authz.policy`` files) and dynamic policies (created and managed via the Policy Management API and persisted in the policy store).
- Dynamic policies can be created, updated, and deleted via the Policy Management API, allowing administrators to adapt policies to changing requirements without modifying service code.
- Using dynamic policies allows for greater flexibility and adaptability, as policies can be modified in response to evolving business needs or security requirements. However, they might also introduce complexity and potential performance overhead if not defined and managed carefully.
- Maintain a clear separation between static policies (shipped with services) and dynamic policies (managed via the policy data store).

Version Static Policies and Make Dynamic Policies Immutable
-----------------------------------------------------------
- Version the ``authz.policy`` files with the service version to ensure that changes to static policies are tracked and can be rolled back if needed.
- Dynamic policies created via the Policy Management API should be immutable once created. To change a dynamic policy, it should be deleted and recreated with the desired changes. This approach ensures that policy changes are auditable and traceable.
- Implement auditing and logging for all policy changes, including who made the change, when it was made, and what the change was. This is crucial for maintaining security and compliance.

#. Authorization Source of Truth and Clients Boundaries
=======================================================

Make the Policy Store the Single Source of Truth
------------------------------------------------
- The ``model.conf`` with the Casbin model configuration and the policy store (via MySQL adapter) together form the single source of truth for authorization in Open edX.
- The policy store contains all dynamic policies and the static policies loaded from the ``authz.policy`` files at service initialization. The policy origin (static vs dynamic) can be tracked via metadata fields if needed.
- The policy store is the single source of truth for authorization rules. By default, services share the same store to ensure consistency and avoid conflicts.

Delegate Policy Ownership to Services
-------------------------------------
- Services are responsible for defining their own policies in the ``authz.policy`` files and managing their own dynamic policies via the Policy Management API.
- These policies are managed by each service according to its domain. For example, the LMS manages courseware access policies, while the CMS manages content creation policies.
- Authorization decisions must always be answered by the service that owns the relevant data and policies (policy owner). For instance, the LMS decides whether a user can access a course because it owns enrollments and courseware data. The CMS decides whether a user can edit content because it owns the content data.

Enforce Consistency via the Open edX Layer
------------------------------------------
- Services do not maintain their own copies of policies or implement their own authorization logic. All authorization decisions are made by the Open edX Layer based on the policies in the policy store.

Allow Shared or Separate Policy Stores as Needed
------------------------------------------------
- By default, all services share the same policy store to ensure consistency and avoid conflicts.
- If isolation between services is required, this can be achieved in two ways: (1) by using a namespace or domain field in the shared table, or (2) by creating a separate policy store for a specific service.

Consequences
************

#. **Clients Share the Same Policy Store**: By default, all services share the same policy store to ensure consistency and avoid conflicts. This means that policies defined by one service can affect authorization decisions in another service.

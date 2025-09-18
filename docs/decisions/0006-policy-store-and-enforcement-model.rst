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

#. Authorization Engine Configuration (``model.conf`` & ``authz.policy``)
=========================================================================

Use a Casbin Model CONF that Supports Core Principles
-----------------------------------------------------
- Use a Casbin configuration model (``model.conf``) that supports Subject-Action-Object-Context checks, explicit scopes, and both RBAC and ABAC features.
- The ``model.conf`` file will be shared across all services unless explicitly overridden for a specific service.
- Explicitly define the effects of policies (allow/deny) and ensure that the default behavior is to deny unless explicitly allowed.
- Favor simple matchers to improve performance and maintainability. This means avoiding complex regexes and nested logic where possible.
- Use Casbin's built-in support for role hierarchies (g, g2) to manage role inheritance and simplify policy definitions.

Do not Handle Grouping and Context Inheritance via Casbin's Built-in Mechanisms
-------------------------------------------------------------------------------
- Grouping resources will not be implemented via Casbin's built-in grouping mechanisms (g, g2) but will be explicitly managed when checking permissions in the application layer. For example, if a user has the ``course_admin`` role in ``org:123``, this will not automatically grant them the ``course_admin`` role in all courses within that org. Instead, the application layer will need to check both the user's role and the specific context (e.g., organization or course) when making authorization decisions.
- Define roles that are context-specific, such as ``course_admin`` for a specific course or ``org_admin`` for a specific organization.

Establish Naming Conventions for Subjects, Actions, Objects, and Contexts
-------------------------------------------------------------------------
- Favor the use of simple and easy to read matchers and policies to keep the system maintainable. Revisit complexity if needed.
- Define clear and consistent naming conventions for subjects, actions, objects, and contexts to ensure uniformity across services:
  - Use namespaces to properly identify the subject, action, object, and context. For example, use ``org:123`` to refer to a specific org with ID 123. The exceptions for this rule are the objects that already have a namespace like ``course-v1:OpenedX+DemoX+DemoCourse`` or ``lib:DemoX:CSPROB``.
  - Use singular verbs for actions (e.g., ``view``, ``edit``, ``delete``) with snake_case formatting when multiple words are needed (e.g., ``view_grades``, ``edit_content``).
  - Use the username as the subject when referring to individual users (e.g., ``alice``, ``bob``).
  - Use clear and descriptive names for roles. (e.g., ``course_admin``, ``content_creator``).

Use ``authz.policy`` Files for Default Policies
-----------------------------------------------
- Each service will ship with an ``authz.policy`` file that defines its default policies which are immutable after load. These provide a baseline set of policies that ensure consistent behavior across deployments.
- The ``authz.policy`` file will be loaded by the Open edX Layer at service initialization and saved in the policy store upon first load. They provide a baseline set of policies that ensure consistent behavior across deployments.
- Default policies should be subjected to load-testing to ensure they do not introduce performance regressions.
- Services can override the default ``authz.policy`` file by providing a custom file path via configuration if needed.
- Document all default policies with in-line comments in the ``authz.policy`` files to explain their purpose and usage.

#. Policy Management and Versioning
====================================

Store Dynamic Policies Directly in the Policy Store
---------------------------------------------------
- Consider two types of policies: static policies (shipped with services in ``authz.policy`` files) and dynamic policies (created and managed via the Policy Management API and persisted in the policy store).
- Dynamic policies created via the Policy Management API will be stored directly in the policy store (MySQL database) using a Casbin adapter.

Differentiate Between Static and Dynamic Policies
-------------------------------------------------
- Static policies (default) should be differentiated from dynamic policies in the policy store using a metadata field (e.g., ``is_static`` boolean field) and should be immutable after being loaded from the ``authz.policy`` file.
- Dynamic policies can be created, updated, and deleted via the Policy Management API, allowing administrators to adapt policies to changing requirements without modifying service code.
- Using dynamic policies allows for greater flexibility and adaptability, as policies can be modified in response to evolving business needs or security requirements. However, they might also introduce complexity and potential performance overhead if not defined and managed carefully.

Version Static Policies and Make Dynamic Policies Immutable
-----------------------------------------------------------
- Version the ``authz.policy`` files with the service version to ensure that changes to static policies are tracked and can be rolled back if needed.
- Dynamic policies created via the Policy Management API should be immutable once created. To change a dynamic policy, it should be deleted and recreated with the desired changes. This approach ensures that policy changes are auditable and traceable.
- Implement auditing and logging for all policy changes, including who made the change, when it was made, and what the change was. This is crucial for maintaining security and compliance.

#. Authorization Source of Truth
=================================

Make the Policy Store the Single Source of Truth
------------------------------------------------
- The ``model.conf`` with the Casbin model configuration (``model.conf``) and the policy store (via MySQL adapter) together form the single source of truth for authorization in Open edX.
- The policy store contains all dynamic policies and the static policies loaded from the ``authz.policy`` files at service initialization.
- The policy store is the single source of truth for authorization rules. By default, services share the same store to ensure consistency and avoid conflicts.

Allow Shared or Separate Policy Stores as Needed
------------------------------------------------
- By default, all services share the same policy store to ensure consistency and avoid conflicts.
- If isolation between services is required, this can be achieved in two ways: (1) by using a namespace or domain field in the shared table, or (2) by creating a separate policy store for a specific service.

#. Authorization Ownership
===========================

Delegate Policy Ownership to Services
-------------------------------------
- Services are responsible for defining their own policies in the ``authz.policy`` files and managing their own dynamic policies via the Policy Management API.
- These policies are managed by each service according to its domain. For example, the LMS manages courseware access policies, while the CMS manages content creation policies.
- Authorization decisions must always be answered by the service that owns the relevant data and policies (policy owner). For instance, the LMS decides whether a user can access a course because it owns enrollments and courseware data. The CMS decides whether a user can edit content because it owns the content data.
- The policy store is by default shared across services, but each service is responsible for its own policies and authorization decisions.

#. Policy Lifecycle
===================

Use a Back-reference Model to Track Domain Objects
--------------------------------------------------
- Use an intermediate back-reference model to track domain objects (e.g., courses, organizations) and their relationships to users and roles.
- Use cascading deletes to ensure that when a domain object is deleted, all associated policies are also removed from the policy store. This helps maintain data integrity and prevents orphaned policies.

Use a Periodic Reconciliation Process to Clean Up Stale Policies
----------------------------------------------------------------
- Implement periodic cleanup tasks to remove stale or orphaned policies that may not be automatically deleted due to unforeseen circumstances.
- This reconciliation process will help maintain the integrity of the policy store and ensure that it reflects the current state of the system.

Create the Record of the Back-reference Model in the same Transaction as the Policy Creation
--------------------------------------------------------------------------------------------
- To ensure data integrity, the creation of the back-reference model record and the corresponding policy in the policy store should occur within the same transaction. This ensures that both operations succeed or fail together.

Consequences
************

#. **Define RBAC in the Casbin Model (``model.conf``)**: The Casbin model configuration (``model.conf``) will define the RBAC structure, including roles, permissions, and the relationships between them. This ensures that the authorization engine can correctly interpret and enforce the defined policies.

#. **ABAC will be Supported Eventually via Custom Matchers**: While the initial implementation will focus on RBAC, the Casbin model will be designed to support ABAC features in the future. This will be achieved through the use of custom matchers that can evaluate attributes of subjects, actions, objects, and contexts.

#. **Default Deny Policy**: The default behavior of the authorization engine will be to deny access unless explicitly allowed by a policy. This is a security best practice that minimizes the risk of unauthorized access.

#. **Grouping will be Handled in the Application Layer**: Instead of using Casbin's built-in grouping mechanisms, the application layer will handle grouping and context inheritance. This provides greater flexibility and allows for more complex authorization logic that is specific to the application's needs.

#. **The Casbin Table Schema will Include Metadata**: The policy store schema will include metadata fields to differentiate between static and dynamic policies. This allows for better management and auditing of policies.

#. **Static Policies will be Immutable**: Policies defined in the ``authz.policy`` files will be immutable after being loaded into the policy store. For a policy to be removed, should go through a deprecation cycle where it is first marked as deprecated and then removed in a future version.

#. **Each Service Should Define Its Own Policies (``authz.policy``)**: Each service is responsible for defining its own policies in the ``authz.policy`` files and managing its own dynamic policies via the Policy Management API. This ensures that services can tailor their authorization rules to their specific needs while maintaining a clear boundary of responsibility. If no defaults are defined, the service will start with an empty policy set.

#. **Clients Share the Same Policy Store**: By default, all services share the same policy store to ensure consistency and avoid conflicts. This means that policies defined by one service can affect authorization decisions in another service.

#. **Making Policies Immutable Might Introduce Operational Complexity**: While making dynamic policies immutable after creation enhances security and auditability, it may introduce operational complexity. Administrators will need to delete and recreate policies to make changes, which could lead to increased administrative overhead.

#. **Performance Considerations**: The use of dynamic policies and complex matchers may introduce performance overhead. It is essential to monitor the performance of the authorization engine and optimize policies and matchers as needed to ensure that authorization checks remain efficient.

#. **For Data Integrity Purposes, Place the Policy Store Where the Data is Owned**: To ensure data integrity and consistency, the policy store should be hosted in the same environment as the services that own the data and policies. If this is not feasible, additional mechanisms must be implemented to maintain consistency like an event-bus mechanism.

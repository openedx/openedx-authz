Glossary
########

.. glossary::
   :sorted:

   Action
      The operation attempted on a resource (e.g., ``view``, ``edit``, ``delete``). Actions use
      snake_case when composed of multiple words (e.g., ``view_grades``). In the :term:`namespace
      convention<Namespace Convention>`, actions are prefixed with ``act^`` (e.g.,
      ``act^content_libraries.view_library``).

   Adapter
      A component that connects the :term:`Authorization Engine` to a data backend for policy
      storage and retrieval. In openedx-authz, the ``ExtendedAdapter`` uses the Django ORM to
      read and write policies in the database, supporting filtered loading for performance.

   Attribute
      A property of a :term:`Subject`, :term:`Resource`, or context used in :term:`ABAC` decisions
      (e.g., ``user.profile.department``, ``course.org``). Attributes enable finer-grained control
      beyond role membership.

   Authorization Check
      The act of asking whether an operation is allowed. Always expressed in :term:`S-A-O-C` form:
      *is Subject allowed to perform Action on Object under Context?*

   Authorization Engine
      The Casbin-based component that evaluates :term:`authorization checks<Authorization Check>`
      against defined policies and returns allow/deny decisions. It loads policies from the
      :term:`Policy Store`, applies the :term:`matcher<Matcher>` logic defined in the
      :term:`model configuration<Model Configuration>`, and is accessed through the
      :term:`Open edX Layer`.

   ABAC
      Attribute-Based Access Control. An :term:`authorization model<Authorization Model>` where
      access decisions are based on attributes of the :term:`subject<Subject>`, object, and context
      (e.g., user's organization, resource type, time of day). ABAC is the long-term goal for
      Open edX authorization.

   Authorization Model
      A framework or approach that defines how to express who can do what, on which
      :term:`resource<Resource>`, and under which conditions. See :term:`RBAC`, :term:`ABAC`,
      and :term:`ReBAC`.

   Dynamic Policy
      A :term:`policy<Policy>` created at runtime through the :term:`Role Management API` or
      Django Admin. Dynamic policies include :term:`role<Role>` assignments (granting a user a role
      in a :term:`scope<Scope>`) and operator-defined policy additions. They are mutable via
      the API but immutable once created (delete and recreate to change). Contrast with
      :term:`Static Policy`.

   Enforcement API
      The public interface through which services request authorization decisions. It consists of
      the Public Python API (``openedx_authz.api``) for in-process clients and the REST API for
      remote clients. Services call the Enforcement API with :term:`subject<Subject>`,
      :term:`action<Action>`, and :term:`scope<Scope>`, and receive an allow/deny decision.

   Enforcer
      The runtime instance of the :term:`Authorization Engine` that evaluates authorization
      requests. Implemented as a singleton (``AuthzEnforcer``) wrapping Casbin's
      ``SyncedEnforcer``, it loads policies from the :term:`Policy Store` and reloads them when
      the policy version changes.

   Feature Flag
      A toggle that controls whether a feature is active. In the AuthZ context, Waffle flags
      control the cutover from legacy authorization to the new system per course, organization,
      or instance. See ADR 0010.

   Matcher
      The logic in the :term:`model configuration<Model Configuration>` that determines whether a
      :term:`policy<Policy>` applies to a given request. The matcher checks :term:`subject<Subject>`
      role membership, :term:`scope<Scope>` patterns (via ``keyMatch``), and :term:`action<Action>`
      grouping (via ``g2``).

   Model Configuration
      The Casbin ``model.conf`` file that defines the structure of authorization requests, policies,
      role definitions, effects, and :term:`matchers<Matcher>`. It is the blueprint for how the
      :term:`Authorization Engine` interprets and evaluates policies. Shared across all services
      by default.

   Namespace Convention
      The naming convention used in policies where a ``^`` separator distinguishes the type prefix
      from the identifier (e.g., ``user^alice``, ``role^course_admin``, ``act^edit``,
      ``lib^lib:DemoX:CSPROB``). This prevents ambiguity between authz namespaces and resource
      identifiers, and enables polymorphic dispatch.

   Open edX Layer
      The ``openedx_authz`` Django app that encapsulates all authorization logic. It abstracts
      the :term:`Authorization Engine` internals and provides the :term:`Enforcement API`,
      :term:`Role Management API`, and policy lifecycle management. Services interact with
      authorization exclusively through this layer.

   Permission
      An atomic unit of access that can be granted or denied (e.g., ``CREATE_COURSE``,
      ``EDIT_ROLE``). Permissions are grouped into :term:`roles<Role>` and expressed as
      :term:`actions<Action>` in policies.

   Policy
      A declarative rule that defines which :term:`subjects<Subject>` can perform which
      :term:`actions<Action>` on which objects under which context, with a specified effect
      (allow or deny). Policies are stored outside of code in the :term:`Policy Store`, versioned,
      and auditable. See also :term:`Static Policy` and :term:`Dynamic Policy`.

   Role Management API
      The interface for managing :term:`role<Role>` assignments, :term:`policies<Policy>`, and
      :term:`dynamic policies<Dynamic Policy>` in the :term:`Policy Store`. Implemented in
      ``openedx_authz.api.roles`` (role assignment, unassignment, and queries) and
      ``openedx_authz.api.users`` (user-oriented convenience wrappers). Accessible through
      Python functions and management commands within the :term:`Open edX Layer`.

   Policy Store
      The persistent storage where all authorization policies are kept. Backed by the Django ORM
      (the ``CasbinRule`` table and related metadata models), it holds both :term:`static
      policies<Static Policy>` and :term:`dynamic policies<Dynamic Policy>`. The Policy Store is
      the single source of truth for authorization rules. By default, all services share the
      same store.

   RBAC
      Role-Based Access Control. An :term:`authorization model<Authorization Model>` where access
      is granted based on :term:`roles<Role>` assigned to users (e.g., "admins can edit any
      record"). See also :term:`Scoped RBAC`.

   ReBAC
      Relationship-Based Access Control. An :term:`authorization model<Authorization Model>` where
      access decisions are based on explicit relationships between :term:`subjects<Subject>` and
      objects, often modeled as a graph. Not adopted for Open edX due to added complexity and
      lack of strong use cases.

   Resource
      The object being accessed or acted upon (e.g., a course, a content library, an organization).
      In policies, resources are identified within the :term:`scope<Scope>` field using the
      :term:`namespace convention<Namespace Convention>`.

   Role
      A named collection of :term:`permissions<Permission>` that can be assigned to a
      :term:`subject<Subject>` within a :term:`scope<Scope>` (e.g., ``course_admin``,
      ``library_editor``). Roles are defined in :term:`static policies<Static Policy>` and
      assigned to users via :term:`dynamic policies<Dynamic Policy>`.

   S-A-O-C
      Subject-Action-Object-Context. The canonical shape of any :term:`authorization
      check<Authorization Check>`: *is Subject allowed to perform Action on Object under Context?*
      All authorization decisions in Open edX are normalized to this form.

   Scope
      The boundary within which a :term:`role<Role>` or :term:`policy<Policy>` applies (e.g.,
      platform-wide, organization-wide, a single course, or a specific library). Scopes are
      first-class citizens in the authorization model: explicitly modeled, parameterized (e.g.,
      ``org^OpenedX``, ``course-v1^course-v1:Org+Course+Run``), and available to policies,
      queries, and audits.

   Scoped RBAC
      A variant of :term:`RBAC` where :term:`roles<Role>` apply within a specific
      :term:`scope<Scope>` (e.g., ``course_admin`` for a particular course, ``org_admin`` for a
      particular organization). Used as the pragmatic first step toward :term:`ABAC`.

   Static Policy
      A :term:`policy<Policy>` defined in the ``authz.policy`` file shipped with the package.
      Static policies define default role-permission mappings and action groupings. They are loaded
      into the :term:`Policy Store` at deployment time via the ``load_policies`` management command
      and are immutable after load. Contrast with :term:`Dynamic Policy`.

   Subject
      The entity requesting access. Typically a user (e.g., ``user^alice``) but can also be a
      service (e.g., ``service^lms``). In the :term:`namespace convention<Namespace Convention>`,
      subjects carry a type prefix that identifies the kind of entity.

   Watcher
      A mechanism for distributed policy synchronization. When one service instance updates
      policies in the :term:`Policy Store`, the watcher notifies other instances to reload their
      in-memory policy state, keeping :term:`enforcers<Enforcer>` consistent across a cluster.

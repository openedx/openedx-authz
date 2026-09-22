Change Log
##########

..
   All enhancements and patches to openedx_authz will be documented
   in this file.  It adheres to the structure of https://keepachangelog.com/ ,
   but in reStructuredText instead of Markdown (for ease of incorporation into
   Sphinx documentation and the PyPI description).

   This project adheres to Semantic Versioning (https://semver.org/).

.. There should always be an "Unreleased" section for changes pending release.

Unreleased
**********

1.26.0 - 2026-09-22
*******************

Added
=====

* Added validation of Paragon ``icon`` names in authorization schema definitions
  (ADR 0017 §4). Category, permission, role, and role-extension icons are now checked
  against the set of names exported by ``@openedx/paragon/icons``, vendored in
  ``openedx_authz/engine/schema/paragon_icons.py`` and regenerated with
  ``make paragon_icons`` (ADR 0026).

1.25.0 - 2026-09-21
*******************

Added
=====

* Added the static authorization schema, a versioned YAML format for declaring permissions,
  permission categories, roles, and role extensions (ADR 0017). The permissions and roles that
  ``authz.policy`` defines are now also expressed as schema files under
  ``openedx_authz/authz/schema/``.
* Added the schema loading pipeline in ``openedx_authz/engine/schema/``, covering the discover,
  load, validate and compile phases of the lifecycle (ADR 0018), plus render and apply in
  ``openedx_authz/engine/renderer.py``.
* Added schema discovery through the ``authz.schema`` entry-point group and the
  ``OPENEDX_AUTHZ_SCHEMA_DIRECTORIES`` setting, so applications can ship authorization definitions
  with their code and operators can contribute them through deployment configuration (ADR 0019).
* Added the ``load_authz_schema`` management command, the single non-interactive deployment entry
  point, with ``--dry-run`` to print the change report without writing, ``--force`` to allow
  removing roles that still have assignments, and repeatable ``--dir`` for CI and local runs.
* Added ``role_extensions`` support: an application or deployment can add or remove permissions and
  replace the display metadata or ``hidden`` flag of an existing static role without copying its
  definition. ``priority`` resolves conflicts; an unresolvable equal-priority conflict stops the run
  before any database change (ADR 0023).
* Added first-class tables for compiled definitions and their provenance, in migration
  ``0011_authz_schema_definitions``: permission categories, permission definitions, role
  definitions, role-permission grants, schema sources, and one source-link table per definition kind
  recording whether a contribution was a base definition or an extension (ADR 0025).
* Added source attribution at the role-permission grain, so contributions from different
  applications to the same role remain distinguishable and queryable through
  ``origins_for_role``, ``origins_for_permission``, ``origins_for_category`` and
  ``origin_for_role_permission``.
* Added a change report before any write: the command lists the policy rows and the definitions that
  would be added, updated or removed, including metadata-only edits that change no policy row
  (ADR 0018 §6).

Notes
=====

* No authorization behavior changes in this release. Loading ``authz.policy`` works as before, and
  the new pipeline runs only when ``load_authz_schema`` is invoked.
* Applying a schema is idempotent and preserves data the loader does not own: user assignments,
  dynamic roles, legacy ``g2`` action-inheritance rows, and pre-existing policy rows that no schema
  declares. Rows that already exist are adopted, gaining definition and source records rather than
  being rewritten (ADR 0025 §6).
* Removing a static role that still has user assignments stops the deployment and reports the
  assignments. ``--force`` removes the role together with its assignments and writes a
  ``RoleAssignmentAudit`` record for each one.

1.24.0 - 2026-09-14
*******************

Changed
=======

* Add assignments array to the response of GET /api/authz/v1/users/ endpoint.
* Add ``assignments_limit`` query parameter (default 3, max 10) to control the number of inline assignments per user.
* Rename ``assignation_count`` to ``assignment_count`` for consistency with the rest of the codebase.
* Add roles query parameter passthrough to the underlying API call.
* Add ``get_scope_display_name_map`` batch helper to ``api/utils.py``.
* Retrieve ``full_name`` from ``UserProfile.name`` instead of ``get_full_name()`` for consistency across serializers.

1.23.0 - 2026-08-13
*******************

Added
=====

* Added ``courses.view_advanced_settings`` permission for read-only access to advanced settings.
* Added ``courses.view_certificates`` permission for read-only access to certificates.
* Added ``courses.view_group_configurations`` permission for read-only access to group configurations.
* Added ``courses.view_library_updates`` permission for read-only access to library updates.
* All four view permissions are granted to all four course roles (Admin, Staff, Editor, Auditor).

1.22.0 - 2026-08-12
*******************

Added
=====

* Role assignment now succeeds for a course/library scope key before its CourseOverview/ContentLibrary
  exists, and links up automatically once the object is created. (#369)

1.21.3 - 2026-08-04
*******************

Fixed
=====

* Scoped the AdminConsole orgs endpoint to the orgs the requesting user has a course or library role in, including org-level and platform-level glob scopes, instead of returning every active org.

1.21.2 - 2026-07-29
*******************

Fixed
=====

* Exclude superadmin entries from the user-specific assignments endpoint following the same pattern as the global assignments endpoint.

1.21.1 - 2026-07-24
*******************

Fixed
=====

* Corrected a mismatched parameter in the queryset builder for scopes.

1.21.0 - 2026-07-14
*******************

Added
=====

* Introduced a new REST API endpoint and utility functions to fetch course authoring waffle flag states. (#358)

1.20.1 - 2026-07-03
*******************

Changed
=======

* Drop superadmin entries from the assignment list endpoint to avoid exposing sensitive information about superadmins to non-superadmin users.

1.20.0 - 2026-07-01
*******************

Added
=====

* Make ``scope`` optional when validating actions: the permission validation API and
  ``/permissions/validate/me`` endpoint now allow checking whether a user holds a
  permission in any scope (via ``is_user_allowed_in_any_scope``) when no scope is provided.

1.19.0 - 2026-06-17
*******************

Added
=====

* Add ``get_user_role_assignments_per_scope_type`` API function to fetch a user's role assignments filtered by scope type.

1.18.0 - 2026-06-09
*******************

Added
=====

* Add platform glob scope for content libraries.

1.17.1 - 2026-06-05
*******************

Fixed
======

* Performance: Fixed an O(N) bottleneck in visible assignments by pre-filtering data before authorization, avoiding repetitive Casbin enforcer evaluations, and caching role permission lookups (#278).

1.17.0 - 2026-06-03
*******************

Added
=====

* Add support for platform glob scopes.

1.16.0 - 2026-05-21
********************

Changed
=======

* (Patched onto newer changes as well as 0.20.1) Removed checks for libraries v2 when
  the enforcer is loaded. This was originally add to improve performance, but a circular
  import on openedx-platform caused it to always default to true. This ensures that the
  enforcer continues to work even if the circular import is resolved.

1.15.0 - 2026-04-30
*******************

Added
=====

* Add support for course permission in Authz REST APIs (#274)

1.14.0 - 2026-04-22
*******************

Added
=====

* Add optional ``orgs`` query param to the ``GET /api/authz/v1/scopes/`` endpoint, that supports filtering results by multiple orgs.

1.13.0 - 2026-04-22
*******************

Added
=====

* Add ``RoleAssignmentAudit`` model to record role assignment and removal events, including operation type, subject, role, scope, actor database ID, and timestamp.
* Emit ``ROLE_ASSIGNMENT_CREATED`` and ``ROLE_ASSIGNMENT_DELETED`` Open edX public signal events via ``transaction.on_commit`` after every successful role assignment or removal.
* Add Django admin for ``RoleAssignmentAudit`` with filters by operation type and scope type (course, content library), date hierarchy, and search by subject, role, and scope.

1.12.0 - 2026-04-20
*******************

Added
=====

* Add automatic course authoring migration mechanism triggered by the ``authz.enable_course_authoring`` waffle flag when it is toggled at course or organization scope.

1.11.0 - 2026-04-16
*******************

Added
=====

* Add bulk scope support to ``PUT /api/authz/v1/roles/users/``: accept a ``scopes`` list field to assign a role across multiple scopes in a single request, while keeping backward compatibility with the existing single ``scope`` field.

1.10.0 - 2026-04-16
*******************

Added
=====

* Add ``scopes/`` endpoint to list all scopes (courses and libraries), sorted by org, with search and pagination support.

1.9.0 - 2026-04-14
*******************

Added
=====

* Add the ``/api/authz/v1/assignments/`` endpoint for listing all user role assignments, to be used in the admin console.

Changed
=======

* Apply view team permissions to the user assignments and team members endpoints.
* Align docstrings and API docs accordingly.

1.8.0 - 2026-04-14
******************

Added
=====

* Add the ``/api/authz/v1/users/<username>/assignments/`` endpoint to get a list of role assignations for a user.

1.7.0 - 2026-04-14
******************

Added
=====

* Add ``users/validate`` endpoint for bulk validation of user identifiers (usernames or emails).

1.6.0 - 2026-04-10
******************

Added
=====

* Add ``users/validate`` endpoint for bulk validation of user identifiers (usernames or emails).
* Add org-wide support to migration commands for forward and backward migration of course authoring permissions.

1.5.0 - 2026-04-09
******************

Added
=====

* Add ``users/`` endpoint to fetch all team members, with optional filters for orgs, scopes, search by username user full name or email, sorting and pagination.

Fixed
=====

* Fix enforcer ``is_admin_or_superuser_check`` that was not taking into account Org glob scopes.

1.4.0 - 2026-04-09
******************

Added
=====

* Add ``orgs/`` endpoint to list and search orgs, with pagination, as required for filters in the Admin Console.

1.3.0 2026-04-08
****************

Added
=====

* Add stub CCX_COACH role/ CCXCourseOverviewData scope to prevent errors when working with CCX courses.
* Add ADR for global scope support for role assignments.

1.2.0 - 2026-03-30
******************

Added
=====

* Add ``get_user_role_assignments_filtered`` api function to fetch user role assignments filtered by user, role, and/or scope.
* Add ``org`` property to ``ContentLibraryData`` and ``CourseOverviewData``.

1.1.0 - 2026-03-17
******************

Added
=====

* Add support for organization global scopes.

1.0.0 - 2026-03-13
******************

Removed
=======

* Dropped support for Python 3.11.

0.23.0 - 2026-02-18
********************

Added
=====

* Add authz_migrate_course_authoring command to migrate legacy CourseAccessRole data to the new Authz (Casbin-based) system
* Add authz_rollback_course_authoring command to rollback Authz roles back to legacy CourseAccessRole
* Support optional --delete flag for controlled cleanup of source permissions after successful migration
* Add migrate_legacy_course_roles_to_authz and migrate_authz_to_legacy_course_roles service functions
* Add unit tests to verify migration and command behavior

Added
=====

* ADR on the AuthZ for Course Authoring Migration Process Details.

0.22.0 - 2026-02-19
********************

* ADR on the AuthZ for Course Authoring implementation plan.
* ADR on the AuthZ for Course Authoring Feature Flag Implementation Details.
* Defined courses roles and permissions mappings, including legacy compatible permissions.

0.21.0 - 2026-02-12
********************

Added
=====

* Add course staff role, permission to manage advanced course settings, and introduce course scope

0.20.1 - 2026-05-21
********************

Changed
=======

* Removed checks for libraries v2 when the enforcer is loaded. This was
  originally add to improve performance, but a circular import on
  openedx-platform caused it to always default to true. This ensures that the
  enforcer continues to work even if the circular import is resolved.

0.20.0 - 2025-11-27
********************

Added
=====

* Add configurable logging level for Casbin enforcer via ``CASBIN_LOG_LEVEL`` setting (defaults to WARNING).


0.19.2 - 2025-11-25
********************

Performance
===========

* Use a RequestCache for is_admin_or_superuser matcher to improve performance.

0.19.1 - 2025-11-25
********************

Fixed
=====

* Use `short_name` instead of `name` from organization when building library key.

0.19.0 - 2025-11-18
********************

Added
=====

* Handle cache invalidation via a uuid in the database to ensure policy reloads
  occur only when necessary.

0.18.0 - 2025-11-17
********************

Added
=====

* Migration to transfer legacy permissions from ContentLibraryPermission to the new Casbin-based authorization model.

0.17.1 - 2025-11-14
********************

Fixed
=====

* Avoid circular import of AuthzEnforcer.

0.17.0 - 2025-11-14
********************

Added
=====

* Signal to clear policies associated to a user when they are retired.

0.16.0 - 2025-11-13
********************

Changed
=======

* **BREAKING**: Update permission format to include app namespace prefix.

Added
=====

* Register ``CasbinRule`` model in the Django admin.
* Register ``ExtendedCasbinRule`` model in the Django admin as an inline model of ``CasbinRule``.

0.15.0 - 2025-11-11
********************

Added
=====

* `ExtendedCasbinRule` model to extend the base CasbinRule model for additional metadata, and cascade delete
  support.

0.14.0 - 2025-11-11
********************

Added
=====

* Implement custom matcher to check for staff and superuser status.

0.13.1 - 2025-11-11
********************

Fixed
=====

* Avoid duplicates when getting scopes for given user and permissions.

0.13.0 - 2025-11-05
********************

Added
=====

* Add support for global scopes instead of generic `sc` scope to support instance-level permissions.

0.12.0 - 2025-10-30
********************

Changed
=======

* Load authorization policies in permission class.

0.11.2 - 2025-10-30
********************

Added
=====

* Consider Content Library V2 toggle only in CMS service variant.

0.11.1 - 2025-10-29
********************

Changed
=======

* Refactor to get permissions' scopes instead of role.

Fixed
=====

* Use correct content library toggle to check if Content Library V2 is enabled.

0.11.0 - 2025-10-29
********************

Added
=====

* Disable auto-save and auto-load of policies if Content Library V2 is disabled.

0.10.1 - 2025-10-28
********************

Fixed
=====

* Fix constants and test class to be able to use it outside this app.

0.10.0 - 2025-10-28
*******************

Added
=====

* New ``get_object()`` method in ScopeData to retrieve underlying domain objects
* Implementation of ``get_object()`` for ContentLibraryData with canonical key validation

Changed
=======

* Refactor ``ContentLibraryData.exists()`` to use ``get_object()`` internally

0.9.1 - 2025-10-28
******************

Fixed
=====

* Fix role user count to accurately filter users assigned to roles within specific scopes instead of across all scopes.

0.9.0 - 2025-10-27
******************

Added
=====

* Function API to retrieve scopes for a given role and subject.

0.8.0 - 2025-10-24
******************

Added
=====

* Allow disabling auto-load and auto-save of policies by setting CASBIN_AUTO_LOAD_POLICY_INTERVAL to -1.

Changed
=======

* Migrate from using pycodestyle and isort to ruff for code quality checks and formatting.
* Enhance enforcement command with dual operational modes (database and file mode).

0.7.0 - 2025-10-23
******************

Added
=====

* Initial migration to establish dependency on casbin_adapter for automatic CasbinRule table creation.

0.6.0 - 2025-10-22
******************

Changed
=======

* Use a SyncedEnforcer with default auto load policy.

Removed
=======

* Remove Casbin Redis watcher from engine configuration.

0.5.0 - 2025-10-21
******************

Added
=====

* Default policy for Content Library roles and permissions.

Fixed
=====

* Add plugin_settings in test settings.
* Update permissions for RoleListView.

0.4.1 - 2025-10-16
******************

Fixed
=====

* Load policy before adding policies in the loading script to avoid duplicates.

0.4.0 - 2025-16-10
******************

Changed
=======

* Initialize enforcer when application is ready to avoid access errors.

0.3.0 - 2025-10-10
******************

Added
=====

* Implementation of REST API for roles and permissions management.

0.2.0 - 2025-10-10
******************

Added
=====

* ADRs for key design decisions.
* Casbin model (CONF) and engine layer for authorization.
* Implementation of public API for roles and permissions management.

0.1.0 - 2025-08-27
******************

Added
=====

* Basic repo structure and initial setup.

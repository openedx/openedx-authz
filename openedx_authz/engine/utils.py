"""Policy loader module.

This module provides functionality to load and manage policy definitions
for the Open edX AuthZ system using Casbin.
"""

import logging
from collections import defaultdict
from collections.abc import Callable
from typing import Any

from casbin import Enforcer
from django.contrib.auth.models import AbstractUser
from django.core.cache import cache

from openedx_authz.api.data import CourseOverviewData, OrgCourseOverviewGlobData, RoleAssignmentData
from openedx_authz.api.roles import get_all_role_assignments_per_scope_type
from openedx_authz.api.users import (
    assign_role_to_user_in_scope,
    batch_assign_role_to_users_in_scope,
    batch_unassign_role_from_users,
)
from openedx_authz.constants.roles import LEGACY_COURSE_ROLE_EQUIVALENCES, LIBRARY_ADMIN, LIBRARY_AUTHOR, LIBRARY_USER
from openedx_authz.models.migrations import AuthzCourseAuthoringMigrationRun, MigrationType, ScopeType

logger = logging.getLogger(__name__)


GROUPING_POLICY_PTYPES = ["g", "g2", "g3", "g4", "g5", "g6"]

# Map new roles back to legacy roles for rollback purposes
COURSE_ROLE_EQUIVALENCES = {v: k for k, v in LEGACY_COURSE_ROLE_EQUIVALENCES.items()}

MIGRATION_LOCK_TIMEOUT = 60 * 60  # 1 hour


def _get_lock_key(scope_type: ScopeType, scope_key: str) -> str:
    """Generate a cache key for migration locking.

    Args:
        scope_type (ScopeType): Type of scope ('course' or 'org')
        scope_key (str): Identifier for the scope

    Returns:
        str: Cache key for the migration run lock
    """
    return f"authz_migration_lock:{scope_type}:{scope_key}"


def _acquire_lock(scope_type: ScopeType, scope_key: str, migration_run_id: int) -> bool:
    """Acquire a lock for migration to prevent concurrent migrations.

    cache.add() returns True only if the key did not exist (lock acquired).
    If it returns False, another migration run is already in progress.

    Args:
        scope_type (ScopeType): Type of scope ('course' or 'org')
        scope_key (str): Identifier for the scope
        migration_run_id (int): Unique migration run identifier
        timeout (int): Lock timeout in seconds

    Returns:
        bool: True if migration run lock was acquired, False otherwise
    """
    lock_key = _get_lock_key(scope_type, scope_key)
    return cache.add(lock_key, migration_run_id, MIGRATION_LOCK_TIMEOUT)


def _release_lock(scope_type: ScopeType, scope_key: str) -> None:
    """Release a migration lock.

    Args:
        scope_type (ScopeType): Type of scope ('course' or 'org')
        scope_key (str): Identifier for the scope
    """
    lock_key = _get_lock_key(scope_type, scope_key)
    cache.delete(lock_key)


def migrate_policy_between_enforcers(
    source_enforcer: Enforcer,
    target_enforcer: Enforcer,
) -> None:
    """Load policies from a Casbin policy file into the Django database model.

    Args:
        source_enforcer (Enforcer): The Casbin enforcer instance to migrate policies from (e.g., file-based).
        target_enforcer (Enforcer): The Casbin enforcer instance to migrate policies to (e.g.,database).
    """
    try:
        # Load latest policies from the source enforcer
        source_enforcer.load_policy()
        policies = source_enforcer.get_policy()
        logger.info(f"Loaded {len(policies)} policies from source enforcer.")

        # Load target enforcer policies to check for duplicates
        target_enforcer.load_policy()
        logger.info(f"Target enforcer has {len(target_enforcer.get_policy())} existing policies before migration.")

        # TODO: this operations use the enforcer directly, which may not be ideal
        # since we have to load the policy after each addition to avoid duplicates.
        # I think we should consider using an API which can validate whether
        # all policies exist before adding them or we have the
        # latest policies loaded in the enforcer.

        for policy in policies:
            if target_enforcer.has_policy(*policy):
                logger.info(f"Policy {policy} already exists in target, skipping.")
                continue
            target_enforcer.add_policy(*policy)

            # Ensure latest policies are loaded in the target enforcer after each addition
            # to avoid duplicates
            target_enforcer.load_policy()

        for grouping_policy_ptype in GROUPING_POLICY_PTYPES:
            try:
                grouping_policies = source_enforcer.get_named_grouping_policy(grouping_policy_ptype)
                for grouping in grouping_policies:
                    if target_enforcer.has_named_grouping_policy(grouping_policy_ptype, *grouping):
                        logger.info(
                            f"Grouping policy {grouping_policy_ptype}, {grouping} already exists in target, skipping."
                        )
                        continue
                    target_enforcer.add_named_grouping_policy(grouping_policy_ptype, *grouping)

                    # Ensure latest policies are loaded in the target enforcer after each addition
                    # to avoid duplicates
                    target_enforcer.load_policy()
            except KeyError as e:
                logger.info(f"Skipping {grouping_policy_ptype} policies: {e} not found in source enforcer.")
        logger.info(f"Successfully loaded policies from {source_enforcer.get_model()} into the database.")
    except Exception as e:
        logger.error(f"Error loading policies from file: {e}")
        raise


def migrate_legacy_permissions(ContentLibraryPermission):
    """
    Migrate legacy permission data to the new Casbin-based authorization model.
    This function reads legacy permissions from the ContentLibraryPermission model
    and assigns equivalent roles in the new authorization system.

    The old Library permissions are stored in the ContentLibraryPermission model, it consists of the following columns:

    - library: FK to ContentLibrary
    - user: optional FK to User
    - group: optional FK to Group
    - access_level: 'admin' | 'author' | 'read'

    In the new Authz model, this would roughly translate to:

    - library: scope
    - user: subject
    - access_level: role

    Now, we don't have an equivalent concept to "Group", for this we will go through the users in the group and assign
    roles independently.

    param ContentLibraryPermission: The ContentLibraryPermission model to use.
    """

    legacy_permissions = ContentLibraryPermission.objects.select_related(
        "library", "library__org", "user", "group"
    ).all()

    # List to keep track of any permissions that could not be migrated
    permissions_with_errors = []

    for permission in legacy_permissions:
        # Migrate the permission to the new model

        # Derive equivalent role based on access level
        access_level_to_role = {
            "admin": LIBRARY_ADMIN,
            "author": LIBRARY_AUTHOR,
            "read": LIBRARY_USER,
        }

        role = access_level_to_role.get(permission.access_level)
        if role is None:
            # This should not happen as there are no more access_levels defined
            # in ContentLibraryPermission, log and skip
            logger.error(f"Unknown access level: {permission.access_level} for User: {permission.user}")
            permissions_with_errors.append(permission)
            continue

        # Generating scope based on library identifier
        scope = f"lib:{permission.library.org.short_name}:{permission.library.slug}"

        if permission.group:
            # Permission applied to a group
            users = [user.username for user in permission.group.user_set.all()]
            logger.info(
                f"Migrating permissions for Users: {users} in Group: {permission.group.name} "
                f"to Role: {role.external_key} in Scope: {scope}"
            )
            batch_assign_role_to_users_in_scope(
                users=users, role_external_key=role.external_key, scope_external_key=scope
            )
        else:
            # Permission applied to individual user
            logger.info(
                f"Migrating permission for User: {permission.user.username} "
                f"to Role: {role.external_key} in Scope: {scope}"
            )

            assign_role_to_user_in_scope(
                user_external_key=permission.user.username,
                role_external_key=role.external_key,
                scope_external_key=scope,
            )

    return permissions_with_errors


def _validate_migration_input(course_id_list, org_id):
    """
    Validate the common inputs for the migration functions.
    """
    if not course_id_list and not org_id:
        raise ValueError(
            "At least one of course_id_list or org_id must be provided to limit the scope of the migration."
        )

    if course_id_list and any(not course_key.startswith("course-v1:") for course_key in course_id_list):
        raise ValueError(
            "Only full course keys (e.g., 'course-v1:org+course+run') are supported in the course_id_list."
            " Other course types such as CCX are not supported."
        )


def _run_scoped_migration(
    migration_type: MigrationType,
    course_id_list: list[str] | None,
    org_id: str | None,
    delete_after_migration: bool,
    process_scope_fn: Callable[[ScopeType, str], tuple[list, list]],
) -> tuple[list, list]:
    """Orchestrate a migration over a set of scopes with per-scope locking and tracking.

    For each scope, creates a ``AuthzCourseAuthoringMigrationRun``, acquires a distributed lock,
    and delegates the work to ``process_scope_fn``. Scopes whose lock cannot be acquired are
    marked SKIPPED.

    Args:
        migration_type (MigrationType): Direction of the migration (forward or rollback).
        course_id_list (list[str] | None): List of course IDs to migrate individually.
            Mutually exclusive with ``org_id``.
        org_id (str | None): Organization ID to migrate as a single org-scoped run.
            Mutually exclusive with ``course_id_list``.
        delete_after_migration (bool): Whether to delete successfully migrated entries after migration.
        process_scope_fn (Callable[[ScopeType, str], tuple[list, list]]): Callable that
            receives ``(scope_type, scope_key)`` and returns a ``(errors, successes)``
            tuple of ``RoleAssignmentData`` lists.

    Returns:
        A tuple of ``(errors, successes)`` aggregated across all processed scopes, where
        each element is a list of ``RoleAssignmentData`` instances.
    """
    scopes_to_process = (
        [(ScopeType.COURSE, course_id) for course_id in course_id_list] if course_id_list else [(ScopeType.ORG, org_id)]
    )

    all_errors = []
    all_successes = []

    for scope_type, scope_key in scopes_to_process:
        metadata = {
            "course_id": scope_key if scope_type == ScopeType.COURSE else None,
            "org_id": org_id if scope_type == ScopeType.ORG else None,
            "delete_after": delete_after_migration,
        }
        migration_run = AuthzCourseAuthoringMigrationRun.create_pending(migration_type, scope_type, scope_key, metadata)

        if not _acquire_lock(scope_type, scope_key, migration_run.id):
            logger.warning(f"Migration already in progress for {scope_type}:{scope_key}.")
            migration_run.mark_skipped(reason="locked")
            continue

        migration_run.mark_running()

        errors, successes = process_scope_fn(scope_type, scope_key)
        all_errors.extend(errors)
        all_successes.extend(successes)

        migration_run.mark_completed(metadata_updates={"success_count": len(successes), "error_count": len(errors)})
        _release_lock(scope_type, scope_key)

    return all_errors, all_successes


def _process_forward_permissions(
    legacy_permissions: list,
    course_access_role_model: Any,
    delete_after_migration: bool,
) -> tuple[list, list]:
    """Process a batch of legacy course role permissions and assign them in the Casbin-based model.

    For each permission, resolves the equivalent Casbin role, determines the scope
    (course or org), and calls ``assign_role_to_user_in_scope``. Permissions with
    unknown roles or missing scope data are collected as errors without raising.
    If ``delete_after_migration`` is ``True``, successfully migrated records are
    deleted from the legacy ``CourseAccessRole`` table.

    Args:
        legacy_permissions (list): ``CourseAccessRole`` instances to migrate.
        course_access_role_model (Any): The ``CourseAccessRole`` Django model class,
            used to delete records after successful migration.
        delete_after_migration (bool): If ``True``, deletes each successfully migrated
            record from the legacy table.

    Returns:
        tuple[list, list]: ``(errors, successes)`` — two lists of ``CourseAccessRole``
            instances. ``errors`` contains records that could not be migrated (unknown
            role, missing scope, or failed assignment); ``successes`` contains those
            that were migrated and, if requested, deleted.
    """
    permissions_with_errors = []
    permissions_with_no_errors = []

    for permission in legacy_permissions:
        role = LEGACY_COURSE_ROLE_EQUIVALENCES.get(permission.role)

        if role is None:
            logger.error(f"Unknown access level: {permission.role} for User: {permission.user}")
            permissions_with_errors.append(permission)
            continue

        if permission.course_id:
            scope_external_key = str(permission.course_id)
        elif permission.org:
            scope_external_key = OrgCourseOverviewGlobData.build_external_key(permission.org)
        else:
            logger.error(
                f"Permission for User: {permission.user.username} has neither course_id nor org defined, skipping."
            )
            permissions_with_errors.append(permission)
            continue

        logger.info(
            f"Migrating permission for User: {permission.user.username} to Role: {role} in Scope: {scope_external_key}"
        )

        is_user_added = assign_role_to_user_in_scope(
            user_external_key=permission.user.username,
            role_external_key=role,
            scope_external_key=scope_external_key,
        )

        if not is_user_added:
            logger.error(
                f"Failed to migrate permission for User: {permission.user.username} "
                f"to Role: {role} in Scope: {scope_external_key}"
            )
            permissions_with_errors.append(permission)
            continue

        permissions_with_no_errors.append(permission)

    if delete_after_migration:
        course_access_role_model.objects.filter(id__in=[p.id for p in permissions_with_no_errors]).delete()
        logger.info(f"Deleted {len(permissions_with_no_errors)} legacy permissions after successful migration.")
        logger.info(f"Retained {len(permissions_with_errors)} legacy permissions that had errors during migration.")

    return permissions_with_errors, permissions_with_no_errors


def migrate_legacy_course_roles_to_authz(course_access_role_model, course_id_list, org_id, delete_after_migration):
    """
    Migrate legacy course role data to the new Casbin-based authorization model.
    This function reads legacy permissions from the CourseAccessRole model
    and assigns equivalent roles in the new authorization system.

    The old Course permissions are stored in the CourseAccessRole model, it consists of the following columns:

    - user: FK to User
    - org: optional Organization string
    - course_id: optional CourseKeyField of Course
    - role: 'instructor' | 'staff' | 'limited_staff' | 'data_researcher'

    In the new Authz model, this would roughly translate to:

    - course_id: scope
    - user: subject
    - role: role

    The scope assigned per row depends on which fields are set:
    - course_id set: course-level scope (e.g. "course-v1:OpenedX+CS101+2024").
    - course_id blank, org set: org-level glob scope (e.g. "course-v1:OpenedX+*").
    - both set: course_id takes precedence as the more specific scope.

    When course_id_list is provided, one MigrationRun record is created per course ID so that each
    course is tracked, locked, and completed independently. When only org_id is provided, a single
    org-scoped MigrationRun is created instead.

    param course_access_role_model: It should be the CourseAccessRole model. This is passed in because the function
    is intended to run within a Django migration context, where direct model imports can cause issues.
    param course_id_list: Optional list of course IDs to filter the migration.
    param org_id: Optional organization ID to filter the migration.
    param delete_after_migration: Whether to delete successfully migrated legacy permissions after migration.
    """
    _validate_migration_input(course_id_list, org_id)

    course_access_role_filter = {}

    if org_id:
        course_access_role_filter["org"] = org_id
    elif course_id_list:
        # Only filter by course_id if org_id is not provided,
        # otherwise we will filter by org_id which is more efficient
        course_access_role_filter["course_id__in"] = course_id_list

    legacy_permissions = list(
        course_access_role_model.objects.filter(**course_access_role_filter).select_related("user").all()
    )

    def process_scope(scope_type: ScopeType, scope_key: str) -> tuple[list, list]:
        """
        Select the appropriate permission slice for the given scope
        and delegate to ``_process_forward_permissions``.

        For course scopes, only permissions whose ``course_id`` matches ``scope_key`` are processed.
        For org scopes, the full ``legacy_permissions`` list is used.
        """
        if scope_type == ScopeType.COURSE:
            scope_permissions = [perm for perm in legacy_permissions if str(perm.course_id) == scope_key]
        else:
            scope_permissions = legacy_permissions
        return _process_forward_permissions(
            legacy_permissions=scope_permissions,
            course_access_role_model=course_access_role_model,
            delete_after_migration=delete_after_migration,
        )

    return _run_scoped_migration(
        migration_type=MigrationType.FORWARD,
        course_id_list=course_id_list,
        org_id=org_id,
        delete_after_migration=delete_after_migration,
        process_scope_fn=process_scope,
    )


def _process_rollback_assignments(
    role_assignments: list[RoleAssignmentData],
    users_by_username: dict[str, AbstractUser],
    course_access_role_model: Any,
    delete_after_migration: bool,
) -> tuple[list, list]:
    """Recreate legacy CourseAccessRole entries from a list of openedx-authz role assignments.

    For each assignment, resolves the corresponding user and role, then calls ``get_or_create``
    on the legacy model to avoid duplicates. Course-scoped assignments populate both ``org``
    and ``course_id``; org-scoped assignments populate only ``org``. Any assignment with an
    unsupported scope type is logged and collected as an error.

    If ``delete_after_migration`` is True, successfully migrated assignments are unassigned
    from the new AuthZ model after all entries have been recreated.

    Args:
        role_assignments: List of openedx-authz role assignments to roll back.
        users_by_username: Mapping of username to User instance, used to resolve the
            user FK for each CourseAccessRole entry.
        course_access_role_model: The ``CourseAccessRole`` Django model. Passed explicitly
            to avoid import issues in Django migration contexts.
        delete_after_migration: If True, unassigns each successfully migrated assignment
            from the new AuthZ model after recreating its legacy entry.

    Returns:
        A tuple of ``(errors, successes)``, where each element is a list of
        ``RoleAssignmentData`` instances. ``errors`` contains assignments that could not
        be migrated; ``successes`` contains those that were migrated successfully.
    """
    roles_with_errors = []
    roles_with_no_errors = []
    unassignments = defaultdict(list)

    for role_assignment in role_assignments:
        try:
            user_external_key = role_assignment.subject.external_key
            role_external_key = role_assignment.roles[0].external_key
            scope_external_key = role_assignment.scope.external_key

            course_access_role_kwargs = {
                "user": users_by_username[user_external_key],
                "role": COURSE_ROLE_EQUIVALENCES[role_external_key],
            }

            if isinstance(role_assignment.scope, CourseOverviewData):
                course_access_role_kwargs["org"] = role_assignment.scope.org
                course_access_role_kwargs["course_id"] = scope_external_key
            elif isinstance(role_assignment.scope, OrgCourseOverviewGlobData):
                course_access_role_kwargs["org"] = role_assignment.scope.org
            else:
                # This would only happen for course roles assigned instance-wide
                # which is not yet supported
                logger.error(
                    f"Unexpected scope type: {type(role_assignment.scope)} for RoleAssignment with "
                    f"scope: {scope_external_key}, user: {user_external_key} and role: {role_external_key}, skipping."
                )
                roles_with_errors.append(role_assignment)
                continue

            course_access_role_model.objects.get_or_create(**course_access_role_kwargs)
            roles_with_no_errors.append(role_assignment)

            logger.info(
                f"Successfully rolled back RoleAssignment for User: {user_external_key} "
                f"in Role: {role_external_key} and Scope: {scope_external_key} "
                f"to legacy CourseAccessRole entry."
            )

            if delete_after_migration:
                unassignments[(role_external_key, scope_external_key)].append(user_external_key)

        except Exception as e:  # pylint: disable=broad-exception-caught
            logger.error(
                f"Error rolling back RoleAssignment for User: {role_assignment.subject.external_key} "
                f"in Role: {role_assignment.roles[0].external_key} and Scope: {role_assignment.scope.external_key}: {e}"
            )
            roles_with_errors.append(role_assignment)

    if delete_after_migration:
        total_unassignments = sum(len(users) for users in unassignments.values())
        logger.info(f"Total of {total_unassignments} role assignments unassigned after successful rollback migration.")
        for (role_external_key, scope), users in unassignments.items():
            logger.info(
                f"Unassigned Role: {role_external_key} from {len(users)} users \n"
                f"in Scope: {scope} after successful rollback migration."
            )
            batch_unassign_role_from_users(
                users=users,
                role_external_key=role_external_key,
                scope_external_key=scope,
            )

    return roles_with_errors, roles_with_no_errors


def migrate_authz_to_legacy_course_roles(
    course_access_role_model, user_subject_model, course_id_list, org_id, delete_after_migration
):
    """
    Migrate permissions from the new Casbin-based authorization model back to the legacy CourseAccessRole model.
    This function reads permissions from the Casbin enforcer and creates equivalent entries in the
    CourseAccessRole model.

    This is essentially the reverse of migrate_legacy_course_roles_to_authz and is intended
    for rollback purposes in case of migration issues.

    To build each CourseAccessRole entry, the function needs:
    - A user: resolved from role assignments in scopes linked to courses.
    - A scope: a CourseOverviewData or OrgCourseOverviewGlobData instance, optionally filtered by course_id or org_id.
    - A role: a role external key that maps to a legacy role in COURSE_ROLE_EQUIVALENCES.

    When course_id_list is provided, one MigrationRun record is created per course ID so that each
    course is tracked, locked, and completed independently. When only org_id is provided, a single
    org-scoped MigrationRun is created instead.

    param course_access_role_model: It should be the CourseAccessRole model. This is passed in because the function
    is intended to run within a Django migration context, where direct model imports can cause issues.
    param user_subject_model: It should be the UserSubject model. This is passed in because the function
    is intended to run within a Django migration context, where direct model imports can cause issues.
    param course_id_list: Optional list of course IDs to filter the migration.
    param org_id: Optional organization ID to filter the migration.
    param delete_after_migration: Whether to unassign successfully migrated permissions
    from the new model after migration.
    """
    _validate_migration_input(course_id_list, org_id)

    role_assignments = get_all_role_assignments_per_scope_type(
        scope_types=[CourseOverviewData, OrgCourseOverviewGlobData]
    )

    user_external_keys = set()
    assignments_by_course = defaultdict(list)
    filtered_assignments = []

    for role_assignment in role_assignments:
        # If org_id is provided, skip assignments that don't belong to the target org
        # including org-level glob and course-level assignments
        if org_id and role_assignment.scope.org != org_id:
            continue
        # Otherwise, keep the assignment
        filtered_assignments.append(role_assignment)

        # collect usernames for the DB query below
        user_external_keys.add(role_assignment.subject.external_key)

        # Only course-level assignments are grouped by course_id
        if isinstance(role_assignment.scope, CourseOverviewData):
            assignments_by_course[role_assignment.scope.course_id].append(role_assignment)

    users_by_username = {
        subject.user.username: subject.user
        for subject in user_subject_model.objects.filter(
            user__username__in=user_external_keys,
        ).select_related("user")
    }

    def process_scope(scope_type: ScopeType, scope_key: str) -> tuple[list, list]:
        """
        Select the appropriate assignment slice for the given scope
        and delegate to ``_process_rollback_assignments``.

        For course scopes, only assignments belonging to that specific course are processed.
        For org scopes, the full ``filtered_assignments`` list is used.
        """
        if scope_type == ScopeType.COURSE:
            scope_assignments = assignments_by_course[scope_key]
        else:
            scope_assignments = filtered_assignments
        return _process_rollback_assignments(
            role_assignments=scope_assignments,
            users_by_username=users_by_username,
            course_access_role_model=course_access_role_model,
            delete_after_migration=delete_after_migration,
        )

    return _run_scoped_migration(
        migration_type=MigrationType.ROLLBACK,
        course_id_list=course_id_list,
        org_id=org_id,
        delete_after_migration=delete_after_migration,
        process_scope_fn=process_scope,
    )

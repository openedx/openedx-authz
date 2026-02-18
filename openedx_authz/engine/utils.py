"""Policy loader module.

This module provides functionality to load and manage policy definitions
for the Open edX AuthZ system using Casbin.
"""

import logging

from casbin import Enforcer

from openedx_authz.api.users import (
    assign_role_to_user_in_scope,
    batch_assign_role_to_users_in_scope,
    batch_unassign_role_from_users,
    get_user_role_assignments,
)
from openedx_authz.constants.roles import (
    COURSE_ADMIN,
    COURSE_DATA_RESEARCHER,
    COURSE_LIMITED_STAFF,
    COURSE_STAFF,
    LIBRARY_ADMIN,
    LIBRARY_AUTHOR,
    LIBRARY_USER,
)

logger = logging.getLogger(__name__)

GROUPING_POLICY_PTYPES = ["g", "g2", "g3", "g4", "g5", "g6"]


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


def migrate_legacy_course_roles_to_authz(CourseAccessRole, delete_after_migration):
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

    param CourseAccessRole: The CourseAccessRole model to use.
    """

    legacy_permissions = CourseAccessRole.objects.select_related("user").all()

    # List to keep track of any permissions that could not be migrated
    permissions_with_errors = []
    permissions_with_no_errors = []

    for permission in legacy_permissions:
        # Migrate the permission to the new model

        # Derive equivalent role based on access level
        map_legacy_role = {
            "instructor": COURSE_ADMIN,
            "staff": COURSE_STAFF,
            "limited_staff": COURSE_LIMITED_STAFF,
            "data_researcher": COURSE_DATA_RESEARCHER,
        }

        role = map_legacy_role.get(permission.role)
        if role is None:
            # This should not happen as there are no more access_levels defined
            # in CourseAccessRole, log and skip
            logger.error(f"Unknown access level: {permission.role} for User: {permission.user}")
            permissions_with_errors.append(permission)
            continue

        # Permission applied to individual user
        logger.info(
            f"Migrating permission for User: {permission.user.username} "
            f"to Role: {role.external_key} in Scope: {permission.course_id}"
        )

        assign_role_to_user_in_scope(
            user_external_key=permission.user.username,
            role_external_key=role.external_key,
            scope_external_key=str(permission.course_id),
        )
        permissions_with_no_errors.append(permission)

    if delete_after_migration:
        CourseAccessRole.objects.filter(id__in=[p.id for p in permissions_with_no_errors]).delete()

    return permissions_with_errors


def migrate_authz_to_legacy_course_roles(CourseAccessRole, UserSubject, delete_after_migration):
    """
    Migrate permissions from the new Casbin-based authorization model back to the legacy CourseAccessRole model.
    This function reads permissions from the Casbin enforcer and creates equivalent entries in the
    CourseAccessRole model.

    This is essentially the reverse of migrate_legacy_course_roles_to_authz and is intended
    for rollback purposes in case of migration issues.
    """
    # 1. Get all users with course-related permissions in the new model by filtering
    # UserSubjects that are linked to CourseScopes with a valid course overview.
    course_subjects = (
        UserSubject.objects.filter(casbin_rules__scope__coursescope__course_overview__isnull=False)
        .select_related("user")
        .distinct()
    )

    roles_with_errors = []

    for course_subject in course_subjects:
        user = course_subject.user
        user_external_key = user.username

        # 2. Get all role assignments for the user
        role_assignments = get_user_role_assignments(user_external_key=user_external_key)

        for assignment in role_assignments:
            scope = assignment.scope.external_key

            course_overview = assignment.scope.get_object()

            for role in assignment.roles:
                # We are only interested in course-related scopes and roles
                if not scope.startswith("course-v1:"):
                    continue

                # Map new roles back to legacy roles
                role_to_legacy_role = {
                    COURSE_ADMIN.external_key: "instructor",
                    COURSE_STAFF.external_key: "staff",
                    COURSE_LIMITED_STAFF.external_key: "limited_staff",
                    COURSE_DATA_RESEARCHER.external_key: "data_researcher",
                }

                legacy_role = role_to_legacy_role.get(role.external_key)
                if legacy_role is None:
                    logger.error(f"Unknown role: {role} for User: {user_external_key}")
                    roles_with_errors.append((user_external_key, role.external_key, scope))
                    continue

                try:
                    # Create legacy CourseAccessRole entry
                    CourseAccessRole.objects.get_or_create(
                        user=user,
                        org=course_overview.org,
                        course_id=scope,
                        role=legacy_role,
                    )
                except Exception as e:  # pylint: disable=broad-exception-caught
                    logger.error(
                        f"Error creating CourseAccessRole for User: "
                        f"{user_external_key}, Role: {legacy_role}, Course: {scope}: {e}"
                    )
                    roles_with_errors.append((user_external_key, role.external_key, scope))
                    continue

                # If we successfully created the legacy role, we can unassign the new role
                if delete_after_migration:
                    batch_unassign_role_from_users(
                        users=[user_external_key],
                        role_external_key=role.external_key,
                        scope_external_key=scope,
                    )
    return roles_with_errors

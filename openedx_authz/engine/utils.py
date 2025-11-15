"""Policy loader module.

This module provides functionality to load and manage policy definitions
for the Open edX AuthZ system using Casbin.
"""

import logging

from casbin import Enforcer

from openedx_authz.api.users import assign_role_to_user_in_scope, batch_assign_role_to_users_in_scope
from openedx_authz.constants.roles import LIBRARY_ADMIN, LIBRARY_AUTHOR, LIBRARY_USER

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
        scope = f"lib:{permission.library.org.name}:{permission.library.slug}"

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

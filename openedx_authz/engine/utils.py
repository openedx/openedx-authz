"""Policy loader module.

This module provides functionality to load and manage policy definitions
for the Open edX AuthZ system using Casbin.
"""

import logging

from casbin import Enforcer

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

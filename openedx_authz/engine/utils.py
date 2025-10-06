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
        for policy in policies:
            if not target_enforcer.has_policy(*policy):
                target_enforcer.add_policy(*policy)

        for grouping_policy_ptype in GROUPING_POLICY_PTYPES:
            try:
                grouping_policies = source_enforcer.get_named_grouping_policy(
                    grouping_policy_ptype
                )
                for grouping in grouping_policies:
                    if not target_enforcer.has_named_grouping_policy(
                        grouping_policy_ptype, *grouping
                    ):
                        target_enforcer.add_named_grouping_policy(
                            grouping_policy_ptype, *grouping
                        )
            except KeyError as e:
                logger.debug(
                    f"Skipping {grouping_policy_ptype} policies: {e} not found in source enforcer."
                )
        logger.info(
            f"Successfully loaded policies from {source_enforcer.get_model()} into the database."
        )
    except Exception as e:
        logger.error(f"Error loading policies from file: {e}")
        raise

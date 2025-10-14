"""Django management command to load policies into the authz Django model.

The command supports:
- Specifying the path to the Casbin policy file. Default is 'openedx_authz/engine/config/authz.policy'.
- Specifying the Casbin model configuration file. Default is 'openedx_authz/engine/config/model.conf'.
- Optionally clearing existing policies in the database before loading new ones.
"""

import os

import casbin
from django.core.management.base import BaseCommand

from openedx_authz import ROOT_DIRECTORY
from openedx_authz.engine.enforcer import AuthzEnforcer
from openedx_authz.engine.utils import migrate_policy_between_enforcers


class Command(BaseCommand):
    """Django management command to load policies into the authorization Django model.

    This command reads policies from a specified Casbin policy file and loads them into
    the Django database model used by the Casbin adapter. This allows for easy management
    and persistence of authorization policies within the Django application.

    Example Usage:
        python manage.py load_policies --policy-file-path /path/to/authz.policy
        python manage.py load_policies --policy-file-path /path/to/authz.policy --model-file-path /path/to/model.conf
        python manage.py load_policies
    """

    help = "Load policies from a Casbin policy file into the Django database model."

    def add_arguments(self, parser) -> None:
        """Add command-line arguments to the argument parser.

        Args:
            parser: The Django argument parser instance to configure.
        """
        parser.add_argument(
            "--policy-file-path",
            type=str,
            default=None,
            help="Path to the Casbin policy file (supports CSV format with policies, roles, and action grouping)",
        )
        parser.add_argument(
            "--model-file-path",
            type=str,
            default=None,
            help="Path to the Casbin model configuration file",
        )

    def handle(self, *args, **options):
        """Execute the policy loading command.

        Loads policies from the specified Casbin policy file into the Django database model.
        Optionally clears existing policies before loading new ones.

        Args:
            *args: Positional command arguments (unused).
            **options: Command options including 'policy_file_path', 'model_file_path', and 'clear_existing'.

        Raises:
            CommandError: If the policy file is not found or loading fails.
        """
        policy_file_path, model_file_path = options["policy_file_path"], options["model_file_path"]
        if policy_file_path is None:
            policy_file_path = os.path.join(
                ROOT_DIRECTORY, "engine", "config", "authz.policy"
            )
        if model_file_path is None:
            model_file_path = os.path.join(
                ROOT_DIRECTORY, "engine", "config", "model.conf"
            )

        source_enforcer = casbin.Enforcer(model_file_path, policy_file_path)
        self.migrate_policies(source_enforcer, AuthzEnforcer.get_enforcer())

    def migrate_policies(self, source_enforcer, target_enforcer):
        """Migrate policies from the source enforcer to the target enforcer.

        This method copies all policies, role assignments, and action groupings
        from the source enforcer (file-based) to the target enforcer (database-backed).
        Optionally clears existing policies in the target before migration.

        Args:
            source_enforcer: The Casbin enforcer instance to migrate policies from.
            target_enforcer: The Casbin enforcer instance to migrate policies to.
        """
        migrate_policy_between_enforcers(source_enforcer, target_enforcer)

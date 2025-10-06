"""Django management command to load policies into the authz Django model.

The command supports:
- Specifying the path to the Casbin policy file. Default is 'openedx_authz/engine/config/authz.policy'.
- Specifying the Casbin model configuration file. Default is 'openedx_authz/engine/config/model.conf'.
- Optionally clearing existing policies in the database before loading new ones.

Example Usage:
    python manage.py load_policies --policy-file-path /path/to/policy.csv
"""

import casbin
from django.core.management.base import BaseCommand

from openedx_authz.engine.enforcer import enforcer as global_enforcer
from openedx_authz.engine.utils import migrate_policy_from_file_to_db


class Command(BaseCommand):
    """Django management command to load policies into the authorization Django model.

    This command reads policies from a specified Casbin policy file and loads them into
    the Django database model used by the Casbin adapter. This allows for easy management
    and persistence of authorization policies within the Django application.

    Example Usage:
        python manage.py load_policies --policy-file-path /path/to/policy.csv
        python manage.py load_policies --policy-file-path /path/to/policy.csv --clear-existing
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
            default="openedx_authz/engine/config/authz.policy",
            help="Path to the Casbin policy file (supports CSV format with policies, roles, and action grouping)",
        )
        parser.add_argument(
            "--model-file-path",
            type=str,
            default="openedx_authz/engine/config/model.conf",
            help="Path to the Casbin model configuration file",
        )
        parser.add_argument(
            "--clear-existing",
            action="store_true",
            help="Clear existing policies in the database before loading new ones",
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
        file_enforcer = casbin.Enforcer(
            options["model_file_path"], options["policy_file_path"]
        )
        global_enforcer.set_watcher(
            None
        )  # Disable watcher during bulk load until it's optional
        self.migrate_policies(file_enforcer, global_enforcer)

    def migrate_policies(self, source_enforcer, target_enforcer):
        """Migrate policies from the source enforcer to the target enforcer.

        This method copies all policies, role assignments, and action groupings
        from the source enforcer (file-based) to the target enforcer (database-backed).
        Optionally clears existing policies in the target before migration.

        Args:
            source_enforcer: The Casbin enforcer instance to migrate policies from.
            target_enforcer: The Casbin enforcer instance to migrate policies to.
        """
        migrate_policy_from_file_to_db(source_enforcer, target_enforcer)

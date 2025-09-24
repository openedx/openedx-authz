"""Django management command to load policies into the authz Django model.

The command supports:
- Specifying the path to the Casbin policy file. Default is 'openedx_authz/engine/config/authz.policy'.
- Specifying the Casbin model configuration file. Default is 'openedx_authz/engine/config/model.conf'.
- Optionally clearing existing policies in the database before loading new ones.

Example Usage:
    python manage.py load_policies --policy-file-path /path/to/policy.csv
"""
import casbin
from django.core.management.base import BaseCommand, CommandError

from openedx_authz.engine.enforcer import enforcer as global_enforcer


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

    help = (
        "Load policies from a Casbin policy file into the Django database model. "
    )

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
        global_enforcer.set_watcher(None)  # Disable watcher during bulk load
        self.migrate_policies(file_enforcer, global_enforcer, options["clear_existing"])

    def migrate_policies(self, source_enforcer, target_enforcer, clear_existing):
        """Migrate policies from the source enforcer to the target enforcer.

        This method copies all policies, role assignments, and action groupings
        from the source enforcer (file-based) to the target enforcer (database-backed).
        Optionally clears existing policies in the target before migration.

        Args:
            source_enforcer: The Casbin enforcer instance to migrate policies from.
            target_enforcer: The Casbin enforcer instance to migrate policies to.
            clear_existing: If True, clear existing policies in the target before migration.
        """
        if clear_existing:
            target_enforcer.clear_policy()
            self.stdout.write(self.style.WARNING("Cleared existing policies in the database."))

        policies = source_enforcer.get_policy()
        for policy in policies:
            target_enforcer.add_policy(*policy)

        for grouping_policy_ptype in ("g", "g2", "g3", "g4", "g5", "g6"):
            try:
                grouping_policies = source_enforcer.get_named_grouping_policy(grouping_policy_ptype)
                for grouping in grouping_policies:
                    target_enforcer.add_named_grouping_policy(grouping_policy_ptype, *grouping)
            except KeyError as e:
                self.stdout.write(self.style.ERROR(f"Failed to migrate {grouping_policy_ptype} policies: {e} not found in source enforcer."))

        target_enforcer.save_policy()
        self.stdout.write(f"✓ Migrated {len(policies)} policies.")

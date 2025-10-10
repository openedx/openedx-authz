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
from openedx_authz.engine.enforcer import enforcer as global_enforcer
from openedx_authz.engine.utils import migrate_policy_between_enforcers


class Command(BaseCommand):
    """Django management command to load policies into the authorization Django model.

    This command reads policies from a specified Casbin policy file and loads them into
    the Django database model used by the Casbin adapter. This allows for easy management
    and persistence of authorization policies within the Django application.

    Example Usage:
        python manage.py load_policies --policy-file-path /path/to/authz.policy
        python manage.py load_policies --policy-file-path /path/to/authz.policy --model-file-path /path/to/model.conf
        python manage.py load_policies --clear-existing
    """

    help = "Load policies from a Casbin policy file into the Django database model."

    def add_arguments(self, parser) -> None:
        """Add command-line arguments to the argument parser."""
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
        parser.add_argument(
            "--clear-existing",
            action="store_true",
            help="Clear all existing policies in the database before loading new ones",
        )

    def handle(self, *args, **options):
        """Execute the policy loading command."""
        policy_file_path = options["policy_file_path"]
        model_file_path = options["model_file_path"]
        clear_existing = options.get("clear_existing", False)

        if policy_file_path is None:
            policy_file_path = os.path.join(
                ROOT_DIRECTORY, "engine", "config", "authz.policy"
            )
        if model_file_path is None:
            model_file_path = os.path.join(
                ROOT_DIRECTORY, "engine", "config", "model.conf"
            )

        source_enforcer = casbin.Enforcer(model_file_path, policy_file_path)

        if clear_existing:
            global_enforcer.clear_policy()

        self.migrate_policies(source_enforcer, global_enforcer)

    def migrate_policies(self, source_enforcer, target_enforcer):
        """Migrate policies from the source enforcer to the target enforcer."""
        migrate_policy_between_enforcers(source_enforcer, target_enforcer)

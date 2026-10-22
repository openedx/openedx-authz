"""Django management command to load Casbin policy files into the authz Django model.

The command supports:

- Specifying the path to a Casbin policy file. Calls without a file are a no-op
  while deployments move to ``load_authz_schema``.
- Specifying the Casbin model configuration file. Default is 'openedx_authz/engine/config/model.conf'.
- Optionally clearing existing policies in the database before loading new ones.
"""

import os

import casbin
import click
from django.core.management.base import BaseCommand

from openedx_authz import ROOT_DIRECTORY
from openedx_authz.engine.enforcer import AuthzEnforcer
from openedx_authz.engine.utils import migrate_policy_between_enforcers


class Command(BaseCommand):
    """Django management command to load policies into the authorization Django model.

    This command reads policies from a specified Casbin policy file and loads them into
    the Django database model used by the Casbin adapter. This allows for easy management
    and persistence of authorization policies within the Django application.

    Example usage::

        python manage.py load_policies --policy-file-path /path/to/custom.policy
        python manage.py load_policies --policy-file-path /path/to/custom.policy --model-file-path /path/to/model.conf
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
            help="Path to a Casbin policy file",
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
            help="Flag to clear existing policies before loading new ones",
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
        policy_file_path, model_file_path = (
            options["policy_file_path"],
            options["model_file_path"],
        )
        if policy_file_path is None:
            self.stdout.write(
                self.style.WARNING(
                    "No policy file supplied; nothing was loaded. "
                    "Use load_authz_schema for static role-permission policies."
                )
            )
            return

        if model_file_path is None:
            model_file_path = os.path.join(ROOT_DIRECTORY, "engine", "config", "model.conf")

        target_enforcer = AuthzEnforcer.get_enforcer()

        if options.get("clear_existing"):
            target_enforcer.load_policy()
            if click.confirm(
                click.style(
                    "Do you want to delete existing roles? "
                    "(This will also delete the assignments related to those roles)",
                    fg="yellow",
                    bold=True,
                ),
                default=False,
            ):
                self._delete_existing_roles(target_enforcer)

        source_enforcer = casbin.Enforcer(model_file_path, policy_file_path)
        self.migrate_policies(source_enforcer, target_enforcer)

    def migrate_policies(self, source_enforcer, target_enforcer):
        """Migrate policies from the source enforcer to the target enforcer.

        This method copies all policies and role assignments
        from the source enforcer (file-based) to the target enforcer (database-backed).
        Optionally clears existing policies in the target before migration.

        Args:
            source_enforcer: The Casbin enforcer instance to migrate policies from.
            target_enforcer: The Casbin enforcer instance to migrate policies to.
        """
        migrate_policy_between_enforcers(source_enforcer, target_enforcer)

    def _delete_existing_roles(self, target_enforcer):
        """Delete existing roles from the target enforcer.

        Args:
            target_enforcer: The Casbin enforcer instance to delete roles from.
        """
        list_of_roles = target_enforcer.get_all_subjects()
        for role in list_of_roles:
            result = target_enforcer.delete_role(role)
            if result:
                click.echo(f"Deleted role: {role}")

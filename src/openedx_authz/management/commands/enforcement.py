"""
Django management command for interactive Casbin enforcement testing.

This command provides an interactive mode for testing authorization enforcement
requests with two operational modes:

1. **Database mode (default)**: Uses AuthzEnforcer with policies from the database

2. **File mode**: Uses a custom Casbin enforcer with policies from files
   - Activated when --policy-file-path and --model-file-path are provided
   - Reads policies directly from the specified CSV file

The command supports:
- Interactive testing with format: subject action scope
- Real-time enforcement results with visual feedback (✓ ALLOWED / ✗ DENIED)
- Display of loaded policies, role assignments, and action grouping rules

Example usage:
    # Use policies from database with default model
    python manage.py lms enforcement

    # Use custom model and policy files
    python manage.py lms enforcement -m /path/to/model.conf -p /path/to/policies.csv

Example test input:
    >>> alice content_libraries.view_library_team lib:OpenedX:CSPROB
    ✓ ALLOWED: alice content_libraries.view_library_team lib:OpenedX:CSPROB
    >>> bob content_libraries.manage_library_team lib:DemoX:LIB1
    ✗ DENIED: bob content_libraries.manage_library_team lib:DemoX:LIB1
"""

import argparse
import os

from casbin import Enforcer
from casbin.util.log import disabled_logging
from django.core.management.base import BaseCommand, CommandError

from openedx_authz import api
from openedx_authz.api.data import ActionData, ScopeData, UserData
from openedx_authz.engine.enforcer import AuthzEnforcer


class Command(BaseCommand):
    """
    Django management command for interactive Casbin enforcement testing.

    This command provides two operational modes for testing authorization:

    1. Database mode (default): Uses AuthzEnforcer with policies from the database.
       This is the default behavior when no arguments are provided.

    2. File mode: Uses a custom Casbin enforcer with policies from files.
       Activated when --policy-file-path and/or --model-file-path are provided.

    The command provides an interactive shell for testing authorization requests
    in real-time with immediate feedback.
    """

    help = (
        "Interactive mode for testing Casbin enforcement policies. By default, uses "
        "AuthzEnforcer with policies from the database. Use --policy-file-path and "
        "--model-file-path to test with custom files instead. "
        "Format: subject action scope."
    )

    def __init__(self, *args, **kwargs):
        """Initialize the command with required attributes."""
        super().__init__(*args, **kwargs)
        self._custom_enforcer = None

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        """Add command-line arguments to the argument parser.

        Args:
            parser (argparse.ArgumentParser): The Django argument parser instance to configure.
        """
        parser.add_argument(
            "-p",
            "--policy-file-path",
            type=str,
            default=None,
            help=(
                "Path to the Casbin policy CSV file. When provided, switches to file mode using a "
                "custom enforcer instead of the database. Supports CSV format with policies, roles, "
                "and action grouping."
            ),
        )
        parser.add_argument(
            "-m",
            "--model-file-path",
            type=str,
            default=None,
            help=(
                "Path to the Casbin model configuration file. When provided, switches to file mode "
                "using a custom enforcer instead of the database. If not specified in file mode, "
                "uses the default model.conf."
            ),
        )

    def handle(self, *args, **options):
        """Execute the enforcement testing command.

        Determines the operational mode based on provided arguments and creates the
        appropriate enforcer instance, then starts the interactive testing mode.

        Operational modes:
        - Database mode: Uses AuthzEnforcer with policies from database (default)
        - File mode: Uses custom Enforcer with policies from files (when files provided)

        Args:
            *args: Positional command arguments (unused).
            **options: Command options including ``--policy-file-path`` and ``--model-file-path``.
        """
        policy_file_path = options["policy_file_path"]
        model_file_path = options["model_file_path"]

        use_file_mode = policy_file_path is not None and model_file_path is not None

        if use_file_mode:
            self._handle_file_mode(policy_file_path, model_file_path)
        else:
            self._handle_database_mode()

    def _handle_database_mode(self) -> None:
        """Handle enforcement testing using AuthzEnforcer with database policies.

        Uses the AuthzEnforcer singleton with policies loaded from the database.
        This is the default mode when no custom files are provided.

        Raises:
            CommandError: If enforcer creation or policy loading fails.
        """
        try:
            enforcer = AuthzEnforcer.get_enforcer()
            enforcer.load_policy()
            disabled_logging()

            self.stdout.write(self.style.SUCCESS("Casbin Interactive Enforcement (Database Mode)"))
            self.stdout.write("Using AuthzEnforcer with policies from database")
            self.stdout.write("")

            self._display_loaded_policies(enforcer)
            self._run_interactive_mode()
        except Exception as e:
            raise CommandError(f"Error creating Casbin enforcer: {str(e)}") from e

    def _handle_file_mode(self, policy_file_path: str, model_file_path: str) -> None:
        """Handle enforcement testing using custom Enforcer with file-based policies.

        Creates a custom Casbin Enforcer instance using the specified model and policy files.
        This mode is useful for testing policies before loading them into the database.

        Args:
            policy_file_path (str): Path to the policy CSV file.
            model_file_path (str): Path to the model configuration file.

        Raises:
            CommandError: If required files are not found or enforcer creation fails.
        """
        if not os.path.isfile(model_file_path):
            raise CommandError(f"Model file not found: {model_file_path}")
        if not os.path.isfile(policy_file_path):
            raise CommandError(f"Policy file not found: {policy_file_path}")

        try:
            enforcer = Enforcer(model_file_path, policy_file_path)

            self.stdout.write(self.style.SUCCESS("Casbin Interactive Enforcement (File Mode)"))
            self.stdout.write(f"Model file: {model_file_path}")
            self.stdout.write(f"Policy file: {policy_file_path}")
            self.stdout.write("")

            self._custom_enforcer = enforcer
            self._display_loaded_policies(enforcer)
            self._run_interactive_mode()
        except Exception as e:
            raise CommandError(f"Error creating Casbin enforcer: {str(e)}") from e

    def _display_loaded_policies(self, enforcer: Enforcer) -> None:
        """Display statistics about loaded policies, roles, and action grouping.

        Args:
            enforcer (Enforcer): The Casbin enforcer instance with loaded policies.
        """
        policies = enforcer.get_policy()
        roles = enforcer.get_grouping_policy()
        action_grouping = enforcer.get_named_grouping_policy("g2")

        self.stdout.write(f"✓ Loaded {len(policies)} policies")
        self.stdout.write(f"✓ Loaded {len(roles)} role assignments")
        self.stdout.write(f"✓ Loaded {len(action_grouping)} action grouping rules")
        self.stdout.write("")

    def _run_interactive_mode(self) -> None:
        """Start the interactive enforcement testing shell.

        Provides a continuous loop where users can input enforcement requests
        in the format 'subject action scope' and receive immediate
        authorization results with visual feedback.

        Note:
            Exit the interactive mode with Ctrl+C or Ctrl+D.
        """
        self.stdout.write(self.style.SUCCESS("Interactive Mode"))
        self.stdout.write("Test custom enforcement requests interactively.")
        self.stdout.write("Enter 'quit', 'exit', or 'q' to exit the interactive mode.")
        self.stdout.write("")
        self.stdout.write("Format: subject action scope")
        self.stdout.write("Example: alice content_libraries.view_library_team lib:OpenedX:CSPROB")
        self.stdout.write("")

        while True:
            try:
                user_input = input("Enter enforcement test: ").strip()

                if not user_input:
                    continue

                if user_input.lower() in ["quit", "exit", "q"]:
                    break

                self._test_interactive_request(user_input)
            except (KeyboardInterrupt, EOFError):
                self.stdout.write(self.style.ERROR("Exiting interactive mode..."))
                break

    def _test_interactive_request(self, user_input: str) -> None:
        """Process and test a single enforcement request from user input.

        Parses the input string, validates the format, executes the enforcement
        check, and displays the result with appropriate styling.

        Args:
            user_input (str): The user's input string in format 'subject action scope'.

        Expected format:
            subject: The requesting entity (e.g., 'alice')
            action: The requested action (e.g., 'content_libraries.view_library_team')
            scope: The authorization context (e.g., 'lib:OpenedX:CSPROB')
        """
        try:
            parts = [part.strip() for part in user_input.split()]
            if len(parts) != 3:
                self.stdout.write(self.style.ERROR(f"✗ Invalid format. Expected 3 parts, got {len(parts)}"))
                self.stdout.write("Format: subject action scope")
                self.stdout.write("Example: alice content_libraries.view_library_team lib:OpenedX:CSPROB")
                return

            subject, action, scope = parts

            if self._custom_enforcer is not None:
                user_data = UserData(external_key=subject)
                action_data = ActionData(external_key=action)
                scope_data = ScopeData(external_key=scope)
                result = self._custom_enforcer.enforce(
                    user_data.namespaced_key,
                    action_data.namespaced_key,
                    scope_data.namespaced_key,
                )
            else:
                result = api.is_user_allowed(subject, action, scope)

            if result:
                self.stdout.write(self.style.SUCCESS(f"✓ ALLOWED: {subject} {action} {scope}"))
            else:
                self.stdout.write(self.style.ERROR(f"✗ DENIED: {subject} {action} {scope}"))
        except (ValueError, IndexError, TypeError) as e:
            self.stdout.write(self.style.ERROR(f"✗ Error processing request: {str(e)}"))

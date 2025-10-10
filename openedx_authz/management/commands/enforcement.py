"""
Django management command for interactive Casbin enforcement testing.

This command creates a Casbin enforcer using the model.conf configuration and a
user-specified policy file, then provides an interactive mode for testing
authorization enforcement requests.

The command supports:
- Loading Casbin model from the built-in model.conf file or a custom file (specified via --model-file-path argument)
- Using custom policy files (specified via --policy-file-path argument)
- Interactive testing with format: subject action scope
- Real-time enforcement results with visual feedback (✓ ALLOWED / ✗ DENIED)
- Display of loaded policies, role assignments, and action grouping rules

Example usage:
    python manage.py enforcement --policy-file-path /path/to/authz.policy

    python manage.py enforcement --policy-file-path /path/to/authz.policy --model-file-path /path/to/model.conf

Example test input:
    user^alice act^read org^OpenedX
"""

import argparse
import os

import casbin
from django.core.management.base import BaseCommand, CommandError

from openedx_authz import ROOT_DIRECTORY


class Command(BaseCommand):
    """
    Django management command for interactive Casbin enforcement testing.

    This command loads a Casbin model configuration and user-specified policy file
    to create an enforcer instance, then provides an interactive shell for testing
    authorization requests in real-time with immediate feedback.
    """

    help = (
        "Interactive mode for testing Casbin enforcement policies using a custom model file and"
        "a custom policy file. Provides real-time authorization testing with format: subject action scope. "
        "Use --policy-file-path to specify the policy file location. "
        "Use --model-file-path to specify the model file location. "
    )

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        """Add command-line arguments to the argument parser.

        Args:
            parser (argparse.ArgumentParser): The Django argument parser instance to configure.
        """
        parser.add_argument(
            "--policy-file-path",
            type=str,
            required=True,
            help="Path to the Casbin policy file (supports CSV format with policies, roles, and action grouping)",
        )
        parser.add_argument(
            "--model-file-path",
            type=str,
            required=False,
            help="Path to the Casbin model file. If not provided, the default model.conf file will be used.",
        )

    def handle(self, *args, **options):
        """Execute the enforcement testing command.

        Loads the Casbin model and policy files, creates an enforcer instance,
        displays configuration summary, and starts the interactive testing mode.

        Args:
            *args: Positional command arguments (unused).
            **options: Command options including `policy_file_path` and `model_file_path`.

        Raises:
            CommandError: If model or policy files are not found or enforcer creation fails.
        """
        model_file_path = (
            self._get_file_path("model.conf") or options["model_file_path"]
        )
        policy_file_path = options["policy_file_path"]

        if not os.path.isfile(model_file_path):
            raise CommandError(f"Model file not found: {model_file_path}")
        if not os.path.isfile(policy_file_path):
            raise CommandError(f"Policy file not found: {policy_file_path}")

        self.stdout.write(self.style.SUCCESS("Casbin Interactive Enforcement"))
        self.stdout.write(f"Model file path: {model_file_path}")
        self.stdout.write(f"Policy file path: {policy_file_path}")
        self.stdout.write("")

        try:
            enforcer = casbin.Enforcer(model_file_path, policy_file_path)
            self.stdout.write(
                self.style.SUCCESS("Casbin enforcer created successfully")
            )

            policies = enforcer.get_policy()
            roles = enforcer.get_grouping_policy()
            action_grouping = enforcer.get_named_grouping_policy("g2")

            self.stdout.write(f"✓ Loaded {len(policies)} policies")
            self.stdout.write(f"✓ Loaded {len(roles)} role assignments")
            self.stdout.write(f"✓ Loaded {len(action_grouping)} action grouping rules")
            self.stdout.write("")

            self._run_interactive_mode(enforcer)

        except Exception as e:
            raise CommandError(f"Error creating Casbin enforcer: {str(e)}") from e

    def _get_file_path(self, file_name: str) -> str:
        """Construct the full file path for a configuration file.

        Args:
            file_name (str): The name of the configuration file (e.g., 'model.conf').

        Returns:
            str: The absolute path to the configuration file in the engine/config directory.
        """
        return os.path.join(ROOT_DIRECTORY, "engine", "config", file_name)

    def _run_interactive_mode(self, enforcer: casbin.Enforcer) -> None:
        """Start the interactive enforcement testing shell.

        Provides a continuous loop where users can input enforcement requests
        in the format 'subject action scope' and receive immediate
        authorization results with visual feedback.

        Args:
            enforcer (casbin.Enforcer): The configured Casbin enforcer instance for testing.

        Note:
            Exit the interactive mode with Ctrl+C or Ctrl+D.
        """
        self.stdout.write(self.style.SUCCESS("Interactive Mode"))
        self.stdout.write("Test custom enforcement requests interactively.")
        self.stdout.write("Enter 'quit', 'exit', or 'q' to exit the interactive mode.")
        self.stdout.write("")
        self.stdout.write("Format: subject action scope")
        self.stdout.write("Example: user^alice act^read org^OpenedX")
        self.stdout.write("")

        while True:
            try:
                user_input = input("Enter enforcement test: ").strip()

                if not user_input:
                    continue

                if user_input.lower() in ["quit", "exit", "q"]:
                    break

                self._test_interactive_request(enforcer, user_input)
            except (KeyboardInterrupt, EOFError):
                self.stdout.write(self.style.ERROR("Exiting interactive mode..."))
                break

    def _test_interactive_request(
        self, enforcer: casbin.Enforcer, user_input: str
    ) -> None:
        """Process and test a single enforcement request from user input.

        Parses the input string, validates the format, executes the enforcement
        check, and displays the result with appropriate styling.

        Args:
            enforcer (casbin.Enforcer): The Casbin enforcer instance to use for testing.
            user_input (str): The user's input string in format 'subject action scope'.

        Expected format:
            subject: The requesting entity (e.g., 'user^alice')
            action: The requested action (e.g., 'act^read')
            scope: The authorization context (e.g., 'org^OpenedX')
        """
        try:
            parts = [part.strip() for part in user_input.split()]
            if len(parts) != 3:
                self.stdout.write(
                    self.style.ERROR(
                        f"✗ Invalid format. Expected 3 parts, got {len(parts)}"
                    )
                )
                self.stdout.write("Format: subject action scope")
                self.stdout.write("Example: user^alice act^read org^OpenedX")
                return

            subject, action, scope = parts
            result = enforcer.enforce(subject, action, scope)

            if result:
                self.stdout.write(
                    self.style.SUCCESS(f"✓ ALLOWED: {subject} {action} {scope}")
                )
            else:
                self.stdout.write(
                    self.style.ERROR(f"✗ DENIED: {subject} {action} {scope}")
                )

        except (ValueError, IndexError, TypeError) as e:
            self.stdout.write(self.style.ERROR(f"✗ Error processing request: {str(e)}"))

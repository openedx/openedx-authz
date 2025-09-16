"""
Django management command for testing Casbin enforcement policies.

This command creates a Casbin enforcer from model.conf and policy.csv files,
then tests enforcement for each request in request.txt.
"""

import os

import casbin
from django.core.management.base import BaseCommand, CommandError

from openedx_authz import ROOT_DIRECTORY


class Command(BaseCommand):
    """
    Test Casbin enforcement policies using model.conf, policy.csv, and request.txt
    """

    help = (
        "Test Casbin enforcement policies using model.conf, policy.csv, and request.txt. "
        "Supports interactive mode for custom testing."
    )

    def add_arguments(self, parser) -> None:
        """Add the arguments to the parser."""
        parser.add_argument(
            "--model-file",
            type=str,
            default=self.get_file_path("model.conf"),
            help="Path to the Casbin model configuration file (default: model.conf)",
        )
        parser.add_argument(
            "--policy-file",
            type=str,
            default=self.get_file_path("authz.policy"),
            help="Path to the policy CSV file (default: authz.policy)",
        )
        parser.add_argument(
            "--request-file",
            type=str,
            default=self.get_file_path("request.sample"),
            help="Path to the request test file (default: request.sample)",
        )
        parser.add_argument(
            "--interactive",
            action="store_true",
            help="Run in interactive mode for testing custom enforcement requests",
        )

    def handle(self, *args, **options):
        """Handle the command."""
        model_file = options["model_file"]
        policy_file = options["policy_file"]
        request_file = options["request_file"]
        interactive_mode = options.get("interactive", False)

        if not os.path.isfile(model_file):
            raise CommandError(f"Model file not found: {model_file}")
        if not os.path.isfile(policy_file):
            raise CommandError(f"Policy file not found: {policy_file}")

        if not interactive_mode:
            if not os.path.isfile(request_file):
                raise CommandError(f"Request file not found: {request_file}")

        self.stdout.write(self.style.SUCCESS("=== Casbin Enforcement Testing ==="))
        self.stdout.write(f"Model file: {model_file}")
        self.stdout.write(f"Policy file: {policy_file}")
        if interactive_mode:
            self.stdout.write("Mode: Interactive")
        else:
            self.stdout.write(f"Request file: {request_file}")
        self.stdout.write("")

        try:
            enforcer = casbin.FastEnforcer(model_file, policy_file)
            self.stdout.write(self.style.SUCCESS("✓ Casbin enforcer created successfully"))

            policies = enforcer.get_policy()
            roles = enforcer.get_grouping_policy()
            role_inheritance = enforcer.get_named_grouping_policy("g2")

            self.stdout.write(f"✓ Loaded {len(policies)} policies")
            self.stdout.write(f"✓ Loaded {len(roles)} role assignments")
            self.stdout.write(f"✓ Loaded {len(role_inheritance)} action inheritance rules")
            self.stdout.write("")

            if interactive_mode:
                self._run_interactive_mode(enforcer)
            else:
                self._process_requests(enforcer, request_file)

        except Exception as e:
            raise CommandError(f"Error creating Casbin enforcer: {str(e)}") from e

    def get_file_path(self, file_name: str) -> str:
        """Get the file path for the given file name."""
        return os.path.join(ROOT_DIRECTORY, "engine", file_name)

    def _process_requests(self, enforcer: casbin.Enforcer, request_file: str) -> None:
        """Process each request in the request file and test enforcement."""
        self.stdout.write(self.style.SUCCESS("=== Processing Enforcement Requests ==="))

        total_requests = 0
        passed_requests = 0
        failed_requests = 0

        with open(request_file, "r") as file:
            for line_num, line in enumerate(file, 1):
                line = line.strip()

                # Skip empty lines and comments
                if not line or line.startswith("#"):
                    continue

                total_requests += 1

                try:
                    # Parse request line: subject, action, object, scope, expected_result
                    parts = [part.strip() for part in line.split(",")]
                    if len(parts) != 5:
                        self.stdout.write(
                            self.style.ERROR(f"Line {line_num}: Invalid format - expected 5 parts, got {len(parts)}")
                        )
                        failed_requests += 1
                        continue

                    subject, action, obj, scope, expected_str = parts
                    expected_result = expected_str.lower() == "true"

                    actual_result = enforcer.enforce(subject, action, obj, scope)

                    if actual_result == expected_result:
                        status = self.style.SUCCESS("✓ PASS")
                        passed_requests += 1
                    else:
                        status = self.style.ERROR("✗ FAIL")
                        failed_requests += 1

                    self.stdout.write(
                        f"{status} Line {line_num:2d}: {subject}, {action}, {obj}, {scope} "
                        f"-> Expected: {expected_result}, Got: {actual_result}"
                    )

                except (ValueError, IndexError) as e:
                    self.stdout.write(self.style.ERROR(f"Line {line_num}: Error processing request - {str(e)}"))
                    failed_requests += 1

        self.stdout.write("")
        self.stdout.write(self.style.SUCCESS("=== Enforcement Test Summary ==="))
        self.stdout.write(f"Total requests: {total_requests}")
        self.stdout.write(self.style.SUCCESS(f"Passed: {passed_requests}"))
        if failed_requests > 0:
            self.stdout.write(self.style.ERROR(f"Failed: {failed_requests}"))
        else:
            self.stdout.write(f"Failed: {failed_requests}")

        success_rate = (passed_requests / total_requests * 100) if total_requests > 0 else 0
        self.stdout.write(f"Success rate: {success_rate:.1f}%")

        if failed_requests == 0:
            self.stdout.write(self.style.SUCCESS("All tests passed!"))
        else:
            self.stdout.write(self.style.WARNING(f"⚠️ {failed_requests} test(s) failed"))

    def _run_interactive_mode(self, enforcer: casbin.Enforcer) -> None:
        """Run interactive mode for testing custom enforcement requests."""
        self.stdout.write(self.style.SUCCESS("=== Interactive Mode ==="))
        self.stdout.write("Test custom enforcement requests interactively.")
        self.stdout.write("Format: subject action object scope")
        self.stdout.write("Example: user:alice act:read lib:test-lib org:OpenedX")
        self.stdout.write("Special commands: help, policies, users, quit")
        self.stdout.write("")

        while True:
            try:
                user_input = input("Enter enforcement test (or command): ").strip()
                if not user_input:
                    continue
                self._test_interactive_request(enforcer, user_input)
            except (KeyboardInterrupt, EOFError):
                break

    def _test_interactive_request(self, enforcer: casbin.Enforcer, user_input: str) -> None:
        """Test a single enforcement request from interactive input."""
        try:
            parts = [part.strip() for part in user_input.split()]
            if len(parts) != 4:
                self.stdout.write(self.style.ERROR(f"✗ Invalid format. Expected 4 parts, got {len(parts)}"))
                self.stdout.write("   Format: subject action object scope")
                self.stdout.write("   Example: user:alice act:read lib:test-lib org:OpenedX")
                return

            subject, action, obj, scope = parts
            result = enforcer.enforce(subject, action, obj, scope)

            if result:
                self.stdout.write(self.style.SUCCESS(f"✓ ALLOWED: {subject} {action} {obj} {scope}"))
            else:
                self.stdout.write(self.style.ERROR(f"✗ DENIED: {subject} {action} {obj} {scope}"))

        except (ValueError, IndexError, TypeError) as e:
            self.stdout.write(self.style.ERROR(f"✗ Error processing request: {str(e)}"))

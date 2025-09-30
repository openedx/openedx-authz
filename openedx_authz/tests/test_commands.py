"""
Tests for the `enforcement` Django management command.
"""

import io
from tempfile import TemporaryFile
from unittest import TestCase
from unittest.mock import Mock, patch

from ddt import data, ddt
from django.core.management import call_command
from django.core.management.base import CommandError

from openedx_authz.management.commands.enforcement import Command as EnforcementCommand


# pylint: disable=protected-access
@ddt
class EnforcementCommandTests(TestCase):
    """
    Tests for the `enforcement` Django management command.

    This test class verifies the behavior of the enforcement command, including:
    - Argument validation and error handling
    - File existence checks for policy and model files
    - Enforcer initialization and error scenarios
    - Interactive mode functionality
    - Command output and user feedback
    """

    def setUp(self):
        super().setUp()
        self.buffer = io.StringIO()
        self.policy_file_path = TemporaryFile()
        self.command = EnforcementCommand()
        self.command.stdout = self.buffer
        self.enforcer = Mock()

    def test_requires_policy_file_argument(self):
        """Test that calling the command without --policy-file-path should error from argparse."""
        with self.assertRaises(CommandError) as ctx:
            call_command("enforcement")

        self.assertEqual("Error: the following arguments are required: --policy-file-path", str(ctx.exception))

    def test_policy_file_not_found_raises(self):
        """Test that command errors when the provided policy file does not exist."""
        non_existent = "invalid/path/does-not-exist.policy"

        with self.assertRaises(CommandError) as ctx:
            call_command("enforcement", policy_file_path=non_existent)

        self.assertEqual(f"Policy file not found: {non_existent}", str(ctx.exception))

    @patch.object(EnforcementCommand, "_get_file_path", return_value="invalid/path/model.conf")
    def test_model_file_not_found_raises(self, mock_get_file_path: Mock):
        """Test that command errors when the provided model file does not exist."""
        with self.assertRaises(CommandError) as ctx:
            call_command("enforcement", policy_file_path=self.policy_file_path.name)

        self.assertEqual(f"Model file not found: {mock_get_file_path.return_value}", str(ctx.exception))

    @patch("openedx_authz.management.commands.enforcement.casbin.Enforcer")
    def test_error_creating_enforcer_raises(self, mock_enforcer_cls: Mock):
        """Test that command errors when the enforcer creation fails."""
        mock_enforcer_cls.side_effect = Exception("Enforcer creation error")

        with self.assertRaises(CommandError) as ctx:
            call_command("enforcement", policy_file_path=self.policy_file_path.name)

        self.assertEqual("Error creating Casbin enforcer: Enforcer creation error", str(ctx.exception))

    @patch("openedx_authz.management.commands.enforcement.casbin.Enforcer")
    @patch.object(EnforcementCommand, "_run_interactive_mode")
    def test_successful_run_prints_summary(self, mock_run_interactive: Mock, mock_enforcer_cls: Mock):
        """
        Test successful command execution with policy file and interactive mode.
        When files exist, command should create enforcer, print counts, and call interactive loop.
        """
        mock_enforcer = Mock()
        policies = [["p", "role:platform_admin", "act:manage", "*", "allow"]]
        roles = [["g", "user:user-1", "role:platform_admin", "*"]]
        action_grouping = [
            ["g2", "act:edit", "act:read"],
            ["g2", "act:edit", "act:write"],
        ]
        mock_enforcer.get_policy.return_value = policies
        mock_enforcer.get_grouping_policy.return_value = roles
        mock_enforcer.get_named_grouping_policy.return_value = action_grouping
        mock_enforcer_cls.return_value = mock_enforcer

        call_command("enforcement", policy_file_path=self.policy_file_path.name, stdout=self.buffer)

        output = self.buffer.getvalue()
        self.assertIn("Casbin Interactive Enforcement", output)
        self.assertIn("Casbin enforcer created successfully", output)
        self.assertIn(f"✓ Loaded {len(policies)} policies", output)
        self.assertIn(f"✓ Loaded {len(roles)} role assignments", output)
        self.assertIn(f"✓ Loaded {len(action_grouping)} action grouping rules", output)
        mock_run_interactive.assert_called_once_with(mock_enforcer)

    def test_run_interactive_mode_displays_help(self):
        """Test that the interactive mode runs."""
        with patch("builtins.input", side_effect=["quit"]):
            self.command._run_interactive_mode(self.enforcer)

        self.assertIn("Interactive Mode", self.buffer.getvalue())
        self.assertIn("Test custom enforcement requests interactively.", self.buffer.getvalue())
        self.assertIn("Enter 'quit', 'exit', or 'q' to exit the interactive mode.", self.buffer.getvalue())
        self.assertIn("Format: subject action scope", self.buffer.getvalue())
        self.assertIn("Example: user:alice act:read org:OpenedX", self.buffer.getvalue())

    def test_run_interactive_mode_maintains_interactive_loop(self):
        """Test that the interactive mode maintains the interactive loop."""
        input_values = ["", "", "", "quit"]

        with patch("builtins.input", side_effect=input_values) as mock_input:
            self.command._run_interactive_mode(self.enforcer)

        self.assertEqual(mock_input.call_count, len(input_values))

    @data(
        ["user:alice act:read org:OpenedX"],
        ["user:bob act:read org:OpenedX"] * 5,
        ["user:john act:read org:OpenedX"] * 10,
    )
    def test_run_interactive_mode_processes_request(self, user_input: list[str]):
        """Test that the interactive mode processes the request."""
        with patch("builtins.input", side_effect=user_input + ["quit"]) as mock_input:
            with patch.object(self.command, "_test_interactive_request") as mock_method:
                self.command._run_interactive_mode(self.enforcer)

        self.assertEqual(mock_input.call_count, len(user_input) + 1)
        self.assertEqual(mock_method.call_count, len(user_input))
        for value in user_input:
            mock_method.assert_any_call(self.enforcer, value)

    @data("quit", "exit", "q", "QUIT", "EXIT", "Q")
    def test_quit_commands_case_insensitive(self, quit_command: str):
        """Test that all quit commands work regardless of case."""
        with patch("builtins.input", side_effect=[quit_command]) as mock_input:
            self.command._run_interactive_mode(self.enforcer)

        self.assertEqual(mock_input.call_count, 1)

    @data(KeyboardInterrupt(), EOFError())
    def test_handles_exceptions(self, exception: Exception):
        """Test that interactive mode handles exceptions gracefully."""
        with patch("builtins.input", side_effect=exception):
            self.command._run_interactive_mode(self.enforcer)

        self.assertIn("Exiting interactive mode...", self.buffer.getvalue())

    def test_interactive_request_allowed(self):
        """Test that `_test_interactive_request` prints allowed output format."""
        self.enforcer.enforce.return_value = True
        user_input = "user:alice act:read org:OpenedX"

        self.command._test_interactive_request(self.enforcer, user_input)

        allowed_output = self.buffer.getvalue()
        self.assertIn(f"✓ ALLOWED: {user_input}", allowed_output)

    def test_interactive_request_denied(self):
        """Test that `_test_interactive_request` prints denied output format."""
        self.enforcer.enforce.return_value = False
        user_input = "user:alice act:delete org:OpenedX"

        self.command._test_interactive_request(self.enforcer, user_input)

        denied_output = self.buffer.getvalue()
        self.assertIn(f"✗ DENIED: {user_input}", denied_output)

    def test_interactive_request_invalid_format(self):
        """Test that `_test_interactive_request` reports invalid input format."""
        user_input = "user:alice act:read"

        self.command._test_interactive_request(self.enforcer, user_input)

        invalid_output = self.buffer.getvalue()
        self.assertIn("✗ Invalid format. Expected 3 parts, got 2", invalid_output)
        self.assertIn("Format: subject action scope", invalid_output)
        self.assertIn(f"Example: {user_input} org:OpenedX", invalid_output)

    @data(ValueError(), IndexError(), TypeError())
    def test_interactive_request_error(self, exception: Exception):
        """Test that `_test_interactive_request` handles processing errors."""
        self.enforcer.enforce.side_effect = exception

        self.command._test_interactive_request(self.enforcer, "user:alice act:read org:OpenedX")

        error_output = self.buffer.getvalue()
        self.assertIn(f"✗ Error processing request: {str(exception)}", error_output)

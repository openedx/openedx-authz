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

from openedx_authz import ROOT_DIRECTORY
from openedx_authz.management.commands.enforcement import Command as EnforcementCommand
from openedx_authz.management.commands.load_policies import Command as LoadPoliciesCommand
from openedx_authz.tests.test_utils import make_action_key, make_scope_key, make_user_key


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

        example_text = f"Example: {make_user_key('alice')} {make_action_key('read')} {make_scope_key('org', 'OpenedX')}"
        self.assertIn("Interactive Mode", self.buffer.getvalue())
        self.assertIn("Test custom enforcement requests interactively.", self.buffer.getvalue())
        self.assertIn("Enter 'quit', 'exit', or 'q' to exit the interactive mode.", self.buffer.getvalue())
        self.assertIn("Format: subject action scope", self.buffer.getvalue())
        self.assertIn(example_text, self.buffer.getvalue())

    def test_run_interactive_mode_maintains_interactive_loop(self):
        """Test that the interactive mode maintains the interactive loop."""
        input_values = ["", "", "", "quit"]

        with patch("builtins.input", side_effect=input_values) as mock_input:
            self.command._run_interactive_mode(self.enforcer)

        self.assertEqual(mock_input.call_count, len(input_values))

    @data(
        [f"{make_user_key('alice')} {make_action_key('read')} {make_scope_key('org', 'OpenedX')}"],
        [f"{make_user_key('bob')} {make_action_key('read')} {make_scope_key('org', 'OpenedX')}"] * 5,
        [f"{make_user_key('john')} {make_action_key('read')} {make_scope_key('org', 'OpenedX')}"] * 10,
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
        user_input = f"{make_user_key('alice')} {make_action_key('read')} {make_scope_key('org', 'OpenedX')}"

        self.command._test_interactive_request(self.enforcer, user_input)

        allowed_output = self.buffer.getvalue()
        self.assertIn(f"✓ ALLOWED: {user_input}", allowed_output)

    def test_interactive_request_denied(self):
        """Test that `_test_interactive_request` prints denied output format."""
        self.enforcer.enforce.return_value = False
        user_input = f"{make_user_key('alice')} {make_action_key('delete')} {make_scope_key('org', 'OpenedX')}"

        self.command._test_interactive_request(self.enforcer, user_input)

        denied_output = self.buffer.getvalue()
        self.assertIn(f"✗ DENIED: {user_input}", denied_output)

    def test_interactive_request_invalid_format(self):
        """Test that `_test_interactive_request` reports invalid input format."""
        user_input = f"{make_user_key('alice')} {make_action_key('read')}"

        self.command._test_interactive_request(self.enforcer, user_input)

        invalid_output = self.buffer.getvalue()
        self.assertIn("✗ Invalid format. Expected 3 parts, got 2", invalid_output)
        self.assertIn("Format: subject action scope", invalid_output)
        self.assertIn(f"Example: {user_input} {make_scope_key('org', 'OpenedX')}", invalid_output)

    @data(ValueError(), IndexError(), TypeError())
    def test_interactive_request_error(self, exception: Exception):
        """Test that `_test_interactive_request` handles processing errors."""
        self.enforcer.enforce.side_effect = exception
        user_input = f"{make_user_key('alice')} {make_action_key('read')} {make_scope_key('org', 'OpenedX')}"

        self.command._test_interactive_request(self.enforcer, user_input)

        error_output = self.buffer.getvalue()
        self.assertIn(f"✗ Error processing request: {str(exception)}", error_output)


class LoadPoliciesCommandTests(TestCase):
    """
    Tests for the `load_policies` Django management command.

    This test class verifies the behavior of the load_policies command, including:
    - Default file path handling
    - Clearing existing policies
    """

    def setUp(self):
        super().setUp()
        self.buffer = io.StringIO()

    @patch('openedx_authz.engine.enforcer.AuthzEnforcer.get_enforcer')
    @patch('casbin.Enforcer')
    @patch('os.path.join')
    @patch('click.confirm')
    def test_handle_with_default_paths(self, mock_confirm, mock_join, mock_casbin_enforcer, mock_get_enforcer):
        """Test handle method with default policy and model paths."""
        # Setup mocks
        mock_target_enforcer = Mock()
        mock_get_enforcer.return_value = mock_target_enforcer

        mock_source_enforcer = Mock()
        mock_casbin_enforcer.return_value = mock_source_enforcer

        policy_path = f"{ROOT_DIRECTORY}/engine/config/authz.policy"
        model_path = f"{ROOT_DIRECTORY}/engine/config/model.conf"

        # Define paths that will be joined
        mock_join.side_effect = (
            policy_path,
            model_path,
        )

        # Create command instance
        command = LoadPoliciesCommand()
        command.migrate_policies = Mock()

        # Call handle method
        command.handle(policy_file_path=None, model_file_path=None, clear_existing=False)

        # Assertions
        mock_casbin_enforcer.assert_called_once_with(
            model_path,
            policy_path,
        )
        mock_join.assert_any_call(
            ROOT_DIRECTORY, "engine", "config", "authz.policy"
        )
        mock_join.assert_any_call(
            ROOT_DIRECTORY, "engine", "config", "model.conf"
        )
        mock_confirm.assert_not_called()
        command.migrate_policies.assert_called_once_with(mock_source_enforcer, mock_target_enforcer)

    @patch('openedx_authz.engine.enforcer.AuthzEnforcer.get_enforcer')
    @patch('casbin.Enforcer')
    @patch('click.confirm')
    def test_handle_with_custom_paths(self, mock_confirm, mock_casbin_enforcer, mock_get_enforcer):
        """Test handle method with custom policy and model paths."""
        # Setup mocks
        mock_target_enforcer = Mock()
        mock_get_enforcer.return_value = mock_target_enforcer

        mock_source_enforcer = Mock()
        mock_casbin_enforcer.return_value = mock_source_enforcer

        # Create command instance
        command = LoadPoliciesCommand()
        command.migrate_policies = Mock()

        # Custom paths
        policy_path = '/custom/path/to/policy.csv'
        model_path = '/custom/path/to/model.conf'

        # Call handle method
        command.handle(policy_file_path=policy_path, model_file_path=model_path, clear_existing=False)

        # Assertions
        mock_casbin_enforcer.assert_called_once_with(model_path, policy_path)
        mock_confirm.assert_not_called()
        command.migrate_policies.assert_called_once_with(mock_source_enforcer, mock_target_enforcer)

    @patch('openedx_authz.engine.enforcer.AuthzEnforcer.get_enforcer')
    @patch('casbin.Enforcer')
    @patch('click.confirm')
    @patch('click.style')
    def test_handle_clear_existing_roles_confirmed(
        self, mock_style, mock_confirm, mock_casbin_enforcer, mock_get_enforcer
    ):
        """Test handle method with clear_existing and confirmed delete roles."""
        # Setup mocks
        mock_target_enforcer = Mock()
        mock_get_enforcer.return_value = mock_target_enforcer

        mock_source_enforcer = Mock()
        mock_casbin_enforcer.return_value = mock_source_enforcer

        # Setup click mocks
        mock_style.return_value = "styled message"
        mock_confirm.side_effect = [True, False]  # Confirm roles, deny permissions

        # Create command instance
        command = LoadPoliciesCommand()
        command.migrate_policies = Mock()
        command._delete_existing_roles = Mock()
        command._delete_permissions_inheritance = Mock()

        # Call handle method
        command.handle(policy_file_path=None, model_file_path=None, clear_existing=True)

        # Assertions
        mock_target_enforcer.load_policy.assert_called_once()
        mock_confirm.assert_called_with(mock_style.return_value, default=False)
        command._delete_existing_roles.assert_called_once_with(mock_target_enforcer)
        command._delete_permissions_inheritance.assert_not_called()
        command.migrate_policies.assert_called_once_with(mock_source_enforcer, mock_target_enforcer)

    @patch('openedx_authz.engine.enforcer.AuthzEnforcer.get_enforcer')
    @patch('casbin.Enforcer')
    @patch('click.confirm')
    @patch('click.style')
    def test_handle_clear_existing_permissions_confirmed(
        self, mock_style, mock_confirm, mock_casbin_enforcer, mock_get_enforcer
    ):
        """Test handle method with clear_existing and confirmed delete permissions."""
        # Setup mocks
        mock_target_enforcer = Mock()
        mock_get_enforcer.return_value = mock_target_enforcer

        mock_source_enforcer = Mock()
        mock_casbin_enforcer.return_value = mock_source_enforcer

        # Setup click mocks
        mock_style.return_value = "styled message"
        mock_confirm.side_effect = [False, True]  # Deny roles, confirm permissions

        # Create command instance
        command = LoadPoliciesCommand()
        command.migrate_policies = Mock()
        command._delete_existing_roles = Mock()
        command._delete_permissions_inheritance = Mock()

        # Call handle method
        command.handle(policy_file_path=None, model_file_path=None, clear_existing=True)

        # Assertions
        mock_target_enforcer.load_policy.assert_called_once()
        mock_confirm.assert_called_with(mock_style.return_value, default=False)
        command._delete_existing_roles.assert_not_called()
        command._delete_permissions_inheritance.assert_called_once_with(mock_target_enforcer)
        command.migrate_policies.assert_called_once_with(mock_source_enforcer, mock_target_enforcer)

    @patch('openedx_authz.engine.enforcer.AuthzEnforcer.get_enforcer')
    @patch('casbin.Enforcer')
    @patch('click.confirm')
    def test_handle_clear_existing_both_denied(self, mock_confirm, mock_casbin_enforcer, mock_get_enforcer):
        """Test handle method with clear_existing but denied deletions."""
        expected_mock_confirm_calls = 2
        # Setup mocks
        mock_target_enforcer = Mock()
        mock_get_enforcer.return_value = mock_target_enforcer

        mock_source_enforcer = Mock()
        mock_casbin_enforcer.return_value = mock_source_enforcer

        # Setup click mocks
        mock_confirm.side_effect = [False, False]  # Deny both roles and permissions

        # Create command instance
        command = LoadPoliciesCommand()
        command.migrate_policies = Mock()
        command._delete_existing_roles = Mock()
        command._delete_permissions_inheritance = Mock()

        # Call handle method
        command.handle(policy_file_path=None, model_file_path=None, clear_existing=True)

        # Assertions
        mock_target_enforcer.load_policy.assert_called_once()
        assert mock_confirm.call_count == expected_mock_confirm_calls
        command._delete_existing_roles.assert_not_called()
        command._delete_permissions_inheritance.assert_not_called()
        command.migrate_policies.assert_called_once_with(mock_source_enforcer, mock_target_enforcer)

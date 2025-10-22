"""
Tests for the `enforcement` Django management command.
"""

import io
from tempfile import NamedTemporaryFile
from unittest import TestCase
from unittest.mock import Mock, patch

from ddt import data, ddt
from django.core.management import call_command
from django.core.management.base import CommandError

from openedx_authz import ROOT_DIRECTORY
from openedx_authz import api as authz_api
from openedx_authz.engine.enforcer import AuthzEnforcer
from openedx_authz.management.commands.load_policies import Command as LoadPoliciesCommand


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
        self.command_name = "enforcement"

        self.policy_file_path = NamedTemporaryFile(suffix=".policy")
        self.model_file_path = NamedTemporaryFile(suffix=".conf")

        self.policies = [
            ["role^library_admin", "act^delete_library", "lib^*", "allow"],
            ["role^library_admin", "act^publish_library", "lib^*", "allow"],
            ["role^library_admin", "act^manage_library_team", "lib^*", "allow"],
        ]
        self.roles = [
            ["user^alice", "role^library_admin", "lib^*"],
        ]
        self.action_grouping = [
            ["act^delete_library", "act^view_library"],
        ]

        self.enforcer = Mock()
        self.enforcer.get_policy.return_value = self.policies
        self.enforcer.get_grouping_policy.return_value = self.roles
        self.enforcer.get_named_grouping_policy.return_value = self.action_grouping

    @patch.object(AuthzEnforcer, "get_enforcer")
    @patch("openedx_authz.management.commands.enforcement.disabled_logging")
    def test_handle_database_mode_default(self, mock_logging: Mock, mock_get_enforcer: Mock):
        """Test database mode is used when no file paths are provided."""
        mock_get_enforcer.return_value = self.enforcer

        with patch("builtins.input", side_effect=["quit"]):
            call_command(self.command_name, stdout=self.buffer)

        output = self.buffer.getvalue()
        self.assertIn("Database Mode", output)
        self.assertIn("AuthzEnforcer", output)
        self.enforcer.load_policy.assert_called_once()
        mock_logging.assert_called_once()

    @patch("openedx_authz.management.commands.enforcement.Enforcer")
    def test_handle_file_mode(self, mock_enforcer_class: Mock):
        """Test file mode is used when both file paths are provided."""
        mock_enforcer_class.return_value = self.enforcer

        with patch("builtins.input", side_effect=["quit"]):
            call_command(
                self.command_name,
                policy_file_path=self.policy_file_path.name,
                model_file_path=self.model_file_path.name,
                stdout=self.buffer,
            )

        output = self.buffer.getvalue()
        self.assertIn("File Mode", output)
        self.assertIn(self.policy_file_path.name, output)
        self.assertIn(self.model_file_path.name, output)
        mock_enforcer_class.assert_called_once_with(self.model_file_path.name, self.policy_file_path.name)

    def test_policy_file_not_found_raises(self):
        """Test that command errors when the provided policy file does not exist."""
        non_existent_policy = "invalid/path/authz.policy"

        with self.assertRaises(CommandError) as ctx:
            call_command(
                self.command_name,
                policy_file_path=non_existent_policy,
                model_file_path=self.model_file_path.name,
            )

        self.assertEqual(f"Policy file not found: {non_existent_policy}", str(ctx.exception))

    def test_model_file_not_found_raises(self):
        """Test that command errors when the provided model file does not exist."""
        non_existent_model = "invalid/path/model.conf"

        with self.assertRaises(CommandError) as ctx:
            call_command(
                self.command_name,
                policy_file_path=self.policy_file_path.name,
                model_file_path=non_existent_model,
            )

        self.assertEqual(f"Model file not found: {non_existent_model}", str(ctx.exception))

    @patch.object(AuthzEnforcer, "get_enforcer")
    def test_display_loaded_policies(self, mock_get_enforcer: Mock):
        """Test that policy statistics are displayed correctly."""
        mock_get_enforcer.return_value = self.enforcer

        with patch("builtins.input", side_effect=["quit"]):
            call_command(self.command_name, stdout=self.buffer)

        output = self.buffer.getvalue()
        self.assertIn(f"✓ Loaded {len(self.policies)} policies", output)
        self.assertIn(f"✓ Loaded {len(self.roles)} role assignments", output)
        self.assertIn(f"✓ Loaded {len(self.action_grouping)} action grouping rules", output)

    @patch.object(AuthzEnforcer, "get_enforcer")
    @patch.object(authz_api, "is_user_allowed")
    def test_interactive_mode_allowed_request(self, mock_is_allowed: Mock, mock_get_enforcer: Mock):
        """Test interactive mode with an allowed enforcement request."""
        mock_get_enforcer.return_value = self.enforcer
        mock_is_allowed.return_value = True

        with patch("builtins.input", side_effect=["alice view_library lib:Org1:LIB1", "quit"]):
            call_command(self.command_name, stdout=self.buffer)

        output = self.buffer.getvalue()
        self.assertIn("✓ ALLOWED: alice view_library lib:Org1:LIB1", output)
        mock_is_allowed.assert_called_once_with("alice", "view_library", "lib:Org1:LIB1")

    @patch.object(AuthzEnforcer, "get_enforcer")
    @patch.object(authz_api, "is_user_allowed")
    def test_interactive_mode_denied_request(self, mock_is_allowed: Mock, mock_get_enforcer: Mock):
        """Test interactive mode with a denied enforcement request."""
        mock_get_enforcer.return_value = self.enforcer
        mock_is_allowed.return_value = False

        with patch("builtins.input", side_effect=["bob delete_library lib:Org2:LIB2", "quit"]):
            call_command(self.command_name, stdout=self.buffer)

        output = self.buffer.getvalue()
        self.assertIn("✗ DENIED: bob delete_library lib:Org2:LIB2", output)
        mock_is_allowed.assert_called_once_with("bob", "delete_library", "lib:Org2:LIB2")

    @patch("openedx_authz.management.commands.enforcement.Enforcer")
    def test_interactive_mode_file_mode_enforcement(self, mock_enforcer_class: Mock):
        """Test that file mode uses custom enforcer for enforcement checks."""
        mock_enforcer_class.return_value = self.enforcer

        with patch("builtins.input", side_effect=["alice view_library lib:Org1:LIB1", "quit"]):
            call_command(
                self.command_name,
                policy_file_path=self.policy_file_path.name,
                model_file_path=self.model_file_path.name,
                stdout=self.buffer,
            )

        output = self.buffer.getvalue()
        self.assertIn("✓ ALLOWED: alice view_library lib:Org1:LIB1", output)
        self.enforcer.enforce.assert_called_once_with("user^alice", "act^view_library", "lib^lib:Org1:LIB1")

    @data(
        "alice",
        "alice view_library",
        "alice view_library lib:Org1:LIB1 lib:Org1:LIB1",
        "alice view_library lib:Org1:LIB1 lib:Org1:LIB1 lib:Org1:LIB1",
    )
    @patch.object(AuthzEnforcer, "get_enforcer")
    def test_interactive_mode_invalid_format(self, user_input: str, mock_get_enforcer: Mock):
        """Test interactive mode handles invalid input format."""
        mock_get_enforcer.return_value = self.enforcer

        with patch("builtins.input", side_effect=[user_input, "quit"]):
            call_command(self.command_name, stdout=self.buffer)

        output = self.buffer.getvalue()
        self.assertIn("✗ Invalid format", output)
        self.assertIn(f"Expected 3 parts, got {len(user_input.split())}", output)

    @patch.object(AuthzEnforcer, "get_enforcer")
    def test_interactive_mode_empty_input(self, mock_get_enforcer: Mock):
        """Test interactive mode handles empty input gracefully."""
        mock_get_enforcer.return_value = self.enforcer

        with patch("builtins.input", side_effect=["", "   ", "quit"]):
            call_command(self.command_name, stdout=self.buffer)

        output = self.buffer.getvalue()
        self.assertIn("Interactive Mode", output)

    @data("quit", "exit", "q", "QUIT", "EXIT", "Q")
    @patch.object(AuthzEnforcer, "get_enforcer")
    def test_interactive_mode_exit_commands(self, exit_cmd: str, mock_get_enforcer: Mock):
        """Test that various exit commands work correctly."""
        mock_get_enforcer.return_value = self.enforcer

        with patch("builtins.input", side_effect=[exit_cmd]):
            call_command(self.command_name, stdout=self.buffer)

        output = self.buffer.getvalue()
        self.assertIn("Interactive Mode", output)

    @data(KeyboardInterrupt(), EOFError())
    @patch.object(AuthzEnforcer, "get_enforcer")
    def test_interactive_mode_keyboard_interrupt(self, exception: Exception, mock_get_enforcer: Mock):
        """Test interactive mode handles KeyboardInterrupt gracefully."""
        mock_get_enforcer.return_value = self.enforcer

        with patch("builtins.input", side_effect=exception):
            call_command(self.command_name, stdout=self.buffer)

        output = self.buffer.getvalue()
        self.assertIn("Exiting interactive mode...", output)

    @patch.object(AuthzEnforcer, "get_enforcer")
    def test_database_mode_enforcer_creation_error(self, mock_get_enforcer: Mock):
        """Test CommandError is raised when enforcer creation fails in database mode."""
        error_message = "Database connection failed"
        mock_get_enforcer.side_effect = Exception(error_message)

        with self.assertRaises(CommandError) as ctx:
            call_command(self.command_name)

        self.assertEqual(f"Error creating Casbin enforcer: {error_message}", str(ctx.exception))
        mock_get_enforcer.assert_called_once()

    @patch("openedx_authz.management.commands.enforcement.Enforcer")
    def test_error_creating_enforcer_raises(self, mock_enforcer_cls: Mock):
        """Test CommandError is raised when the enforcer creation fails in file mode."""
        error_message = "Enforcer creation error"
        mock_enforcer_cls.side_effect = Exception(error_message)

        with self.assertRaises(CommandError) as ctx:
            call_command(
                self.command_name,
                policy_file_path=self.policy_file_path.name,
                model_file_path=self.model_file_path.name,
            )

        self.assertEqual(f"Error creating Casbin enforcer: {error_message}", str(ctx.exception))
        mock_enforcer_cls.assert_called_once_with(self.model_file_path.name, self.policy_file_path.name)

    @data(ValueError("Value error"), TypeError("Type error"), IndexError("Index error"))
    @patch.object(AuthzEnforcer, "get_enforcer")
    @patch.object(authz_api, "is_user_allowed")
    def test_interactive_request_error(self, exception: Exception, mock_is_allowed: Mock, mock_get_enforcer: Mock):
        """Test interactive mode handles enforcement errors gracefully."""
        mock_get_enforcer.return_value = self.enforcer
        mock_is_allowed.side_effect = exception

        with patch("builtins.input", side_effect=["alice view_library lib:Org1:LIB1", "quit"]):
            call_command(self.command_name, stdout=self.buffer)

        output = self.buffer.getvalue()
        self.assertIn("✗ Error processing request:", output)
        self.assertIn(str(exception), output)


# pylint: disable=protected-access
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

    @patch("openedx_authz.engine.enforcer.AuthzEnforcer.get_enforcer")
    @patch("casbin.Enforcer")
    @patch("os.path.join")
    @patch("click.confirm")
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
        mock_join.assert_any_call(ROOT_DIRECTORY, "engine", "config", "authz.policy")
        mock_join.assert_any_call(ROOT_DIRECTORY, "engine", "config", "model.conf")
        mock_confirm.assert_not_called()
        command.migrate_policies.assert_called_once_with(mock_source_enforcer, mock_target_enforcer)

    @patch("openedx_authz.engine.enforcer.AuthzEnforcer.get_enforcer")
    @patch("casbin.Enforcer")
    @patch("click.confirm")
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
        policy_path = "/custom/path/to/policy.csv"
        model_path = "/custom/path/to/model.conf"

        # Call handle method
        command.handle(
            policy_file_path=policy_path,
            model_file_path=model_path,
            clear_existing=False,
        )

        # Assertions
        mock_casbin_enforcer.assert_called_once_with(model_path, policy_path)
        mock_confirm.assert_not_called()
        command.migrate_policies.assert_called_once_with(mock_source_enforcer, mock_target_enforcer)

    @patch("openedx_authz.engine.enforcer.AuthzEnforcer.get_enforcer")
    @patch("casbin.Enforcer")
    @patch("click.confirm")
    @patch("click.style")
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

    @patch("openedx_authz.engine.enforcer.AuthzEnforcer.get_enforcer")
    @patch("casbin.Enforcer")
    @patch("click.confirm")
    @patch("click.style")
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

    @patch("openedx_authz.engine.enforcer.AuthzEnforcer.get_enforcer")
    @patch("casbin.Enforcer")
    @patch("click.confirm")
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

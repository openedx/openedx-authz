"""
Phase 7 — Policy file + management commands security tests.

Groups:
    1. TestLoadPoliciesPathHandling  — load_policies passes paths to casbin.Enforcer with no
       validation. As opposed to the enforcement command, which validates paths before
       construction and raises CommandError on failure.
    2. TestLoadPoliciesIntegration  — call_command('load_policies') end-to-end with a real DB.
    3. TestDeletePolicyHelpers      — _delete_existing_roles / _delete_permissions_inheritance
       integration: verify they actually remove DB rows.
    4. TestActorIdNullSemantics     — ROLE_ASSIGNMENT_CREATED / DELETED fire with actor_id=None
       when called outside a web-request context (management-command use-case).
"""

import os
import tempfile
from importlib.resources import files
from unittest.mock import Mock, patch

from casbin_adapter.models import CasbinRule
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase
from openedx_events.authz.signals import ROLE_ASSIGNMENT_CREATED, ROLE_ASSIGNMENT_DELETED

from openedx_authz.api.data import RoleData, ScopeData, SubjectData
from openedx_authz.api.roles import assign_role_to_subject_in_scope, unassign_role_from_subject_in_scope
from openedx_authz.engine.enforcer import AuthzEnforcer
from openedx_authz.management.commands.load_policies import Command as LoadPoliciesCommand
from openedx_authz.tests.api.test_roles import BaseRolesTestCase

P_USER = "alice"
LIB_SCOPE = "lib:OrgP7:LibP7"
LIB_ROLE = "library_admin"

_MODEL_PATH = str(files("openedx_authz.engine").joinpath("config/model.conf"))
_POLICY_PATH = str(files("openedx_authz.engine").joinpath("config/authz.policy"))


# Group 1 — load_policies: path handling
class TestLoadPoliciesPathHandling(TestCase):
    """
    load_policies passes --policy-file-path / --model-file-path directly to
    casbin.Enforcer() without any existence check or path-containment guard.

    The enforcement command validates paths before construction and raises
    CommandError("… not found: …").  load_policies has no equivalent guard, so
    raw I/O errors escape handle() as unhandled exceptions.
    """

    @patch("openedx_authz.management.commands.load_policies.AuthzEnforcer.get_enforcer")
    def test_nonexistent_policy_file_escapes_as_raw_exception(self, mock_get_enforcer):
        """
        Non-existent --policy-file-path propagates as a raw exception, not CommandError.

        Root cause: handle() has no os.path.isfile() guard on the policy path.
        The enforcement command raises CommandError("Policy file not found: …");
        load_policies does not, so callers see a cryptic IOError / FileNotFoundError.
        """
        mock_get_enforcer.return_value = Mock()
        command = LoadPoliciesCommand()
        with self.assertRaises(Exception) as ctx:
            command.handle(
                policy_file_path="/nonexistent/policy.csv",
                model_file_path=_MODEL_PATH,
                clear_existing=False,
            )
        self.assertNotIsInstance(
            ctx.exception,
            CommandError,
            "Expected raw exception (not CommandError) — load_policies has no path guard",
        )

    @patch("openedx_authz.management.commands.load_policies.AuthzEnforcer.get_enforcer")
    def test_nonexistent_model_file_escapes_as_raw_exception(self, mock_get_enforcer):
        """
        Non-existent --model-file-path propagates as a raw exception, not CommandError.
        """
        mock_get_enforcer.return_value = Mock()
        command = LoadPoliciesCommand()
        with self.assertRaises(Exception) as ctx:
            command.handle(
                policy_file_path=_POLICY_PATH,
                model_file_path="/nonexistent/audit_p7/model.conf",
                clear_existing=False,
            )
        self.assertNotIsInstance(ctx.exception, CommandError)

    @patch("openedx_authz.management.commands.load_policies.AuthzEnforcer.get_enforcer")
    @patch("openedx_authz.management.commands.load_policies.migrate_policy_between_enforcers")
    def test_path_outside_project_directory_is_accepted(self, mock_migrate, mock_get_enforcer):
        """
        A policy file in /tmp (outside the project) is accepted without restriction.

        There is no allowlist or path-containment check.  Any file readable by
        the Django process can be used as the policy source.
        """
        mock_get_enforcer.return_value = Mock()
        with tempfile.NamedTemporaryFile(suffix=".csv", mode="w", dir="/tmp", delete=False) as tmp:
            tmp.write("")  # empty file — Casbin loads zero policies
            tmp_path = tmp.name
        try:
            command = LoadPoliciesCommand()
            # Must not raise CommandError("path not in allowed location")
            command.handle(
                policy_file_path=tmp_path,
                model_file_path=_MODEL_PATH,
                clear_existing=False,
            )
            mock_migrate.assert_called_once()
        finally:
            os.unlink(tmp_path)

    @patch("openedx_authz.management.commands.load_policies.AuthzEnforcer.get_enforcer")
    def test_traversal_sequences_are_not_sanitized(self, mock_get_enforcer):
        """
        Path traversal sequences reach casbin.Enforcer() un-normalised.

        The command does not call os.path.realpath() / os.path.normpath() on
        caller-supplied paths before passing them to casbin.Enforcer().  A path
        like '../../../etc/passwd' escapes the config directory.  Casbin will
        fail to parse most system files as valid policy CSV, but the guard is
        Casbin's parser — not the command's own validation.
        """
        mock_get_enforcer.return_value = Mock()
        config_dir = str(files("openedx_authz.engine").joinpath("config"))
        traversal = os.path.join(config_dir, "../../../etc/passwd")
        self.assertFalse(
            os.path.normpath(traversal).startswith(config_dir),
            "Traversal path must escape the config directory for this test to be meaningful",
        )
        # Casbin will try to parse /etc/passwd and fail — but as a raw error, not CommandError
        with self.assertRaises(Exception) as ctx:
            LoadPoliciesCommand().handle(
                policy_file_path=traversal,
                model_file_path=_MODEL_PATH,
                clear_existing=False,
            )
        self.assertNotIsInstance(ctx.exception, CommandError)


# Group 2 — load_policies: call_command integration with real DB
class TestLoadPoliciesIntegration(BaseRolesTestCase):
    """
    call_command('load_policies') end-to-end against the real test DB.

    BaseRolesTestCase pre-seeds the DB with the full authz.policy rule set, so
    these tests verify idempotency: a second call must not add duplicate rows.
    """

    def test_call_command_with_defaults_succeeds(self):
        """
        call_command('load_policies') completes without raising.
        """
        call_command("load_policies")

    def test_call_command_is_idempotent(self):
        """
        Running load_policies twice leaves CasbinRule row count unchanged.
        """
        count_before = CasbinRule.objects.count()
        call_command("load_policies")
        count_after = CasbinRule.objects.count()
        self.assertEqual(
            count_before,
            count_after,
            "load_policies must not create duplicate CasbinRule rows on a re-run",
        )

    def test_call_command_with_explicit_real_paths(self):
        """Passing explicit real paths also leaves the DB unchanged (idempotent)."""
        count_before = CasbinRule.objects.count()
        call_command("load_policies", policy_file_path=_POLICY_PATH, model_file_path=_MODEL_PATH)
        count_after = CasbinRule.objects.count()
        self.assertEqual(count_before, count_after)


# Group 3 — _delete_existing_roles / _delete_permissions_inheritance integration
class TestDeletePolicyHelpers(BaseRolesTestCase):
    """
    Integration tests for the two helper methods on LoadPoliciesCommand.

    Each test runs within a savepoint (courtesy of Django's TestCase), so the
    DB deletions are rolled back and do not affect other tests.
    """

    def test_delete_existing_roles_removes_all_subjects(self):
        """
        _delete_existing_roles(enforcer) removes all p-policy subjects from the enforcer.
        """
        enforcer = AuthzEnforcer.get_enforcer()
        enforcer.load_policy()
        subjects_before = enforcer.get_all_subjects()
        self.assertGreater(
            len(subjects_before),
            0,
            "Enforcer must have subjects from authz.policy for this test to be meaningful",
        )
        with patch("click.echo"):  # suppress click output during test
            LoadPoliciesCommand()._delete_existing_roles(enforcer)  # pylint: disable=protected-access
        enforcer.load_policy()
        self.assertEqual(
            enforcer.get_all_subjects(),
            [],
            "_delete_existing_roles must remove all role subjects",
        )

    def test_delete_permissions_inheritance_removes_all_g2_policies(self):
        """
        _delete_permissions_inheritance(enforcer) removes all g2 grouping policies.
        """
        enforcer = AuthzEnforcer.get_enforcer()
        enforcer.load_policy()
        g2_before = enforcer.get_named_grouping_policy("g2")
        self.assertGreater(
            len(g2_before),
            0,
            "Enforcer must have g2 rules from authz.policy for this test to be meaningful",
        )
        with patch("click.echo"):
            LoadPoliciesCommand()._delete_permissions_inheritance(enforcer)  # pylint: disable=protected-access
        enforcer.load_policy()
        self.assertEqual(
            enforcer.get_named_grouping_policy("g2"),
            [],
            "_delete_permissions_inheritance must remove all g2 policies",
        )


# Group 4 — actor_id=None semantics outside web-request context
class TestActorIdNullSemantics(BaseRolesTestCase):
    """
    ROLE_ASSIGNMENT_CREATED / DELETED carry actor_id=None when assign/unassign
    runs without a Django request (e.g., from a management command).

    crum.get_current_user() returns None outside a request, so
    getattr(get_current_user(), 'id', None) evaluates to None.  Management-command
    bulk operations therefore produce audit events with no actor attribution.
    """

    def test_assign_role_event_has_null_actor_id_outside_request(self):
        """
        ROLE_ASSIGNMENT_CREATED fires with actor_id=None when no request user.
        """
        subject = SubjectData(external_key=P_USER)
        role = RoleData(external_key=LIB_ROLE)
        scope = ScopeData(external_key=LIB_SCOPE)

        with patch("openedx_authz.api.roles.transaction.on_commit", side_effect=lambda f: f()):
            with patch.object(ROLE_ASSIGNMENT_CREATED, "send_event") as mock_send:
                assign_role_to_subject_in_scope(subject, role, scope)

        mock_send.assert_called_once()
        event_data = mock_send.call_args.kwargs["role_assignment"]
        self.assertIsNone(
            event_data.actor_id,
            "actor_id must be None when called outside a web-request context",
        )

    def test_unassign_role_event_has_null_actor_id_outside_request(self):
        """
        ROLE_ASSIGNMENT_DELETED fires with actor_id=None when no request user.
        """
        subject = SubjectData(external_key=P_USER)
        role = RoleData(external_key=LIB_ROLE)
        scope = ScopeData(external_key=LIB_SCOPE)

        assign_role_to_subject_in_scope(subject, role, scope)

        with patch("openedx_authz.api.roles.transaction.on_commit", side_effect=lambda f: f()):
            with patch.object(ROLE_ASSIGNMENT_DELETED, "send_event") as mock_send:
                unassign_role_from_subject_in_scope(subject, role, scope)

        mock_send.assert_called_once()
        event_data = mock_send.call_args.kwargs["role_assignment"]
        self.assertIsNone(
            event_data.actor_id,
            "actor_id must be None when called outside a web-request context",
        )

    def test_assign_role_event_actor_id_populated_with_request_user(self):
        """
        Reverse for other tests, actor_id is set correctly when a request
        user is present.

        This confirms the None in the management-command path is due to the
        absent current user, not a bug in the event-sending code itself.
        """
        subject = SubjectData(external_key=P_USER + "_control")
        role = RoleData(external_key=LIB_ROLE)
        scope = ScopeData(external_key=LIB_SCOPE + "_ctrl")

        mock_user = Mock()
        mock_user.id = 99

        with patch("openedx_authz.api.roles.get_current_user", return_value=mock_user):
            with patch("openedx_authz.api.roles.transaction.on_commit", side_effect=lambda f: f()):
                with patch.object(ROLE_ASSIGNMENT_CREATED, "send_event") as mock_send:
                    assign_role_to_subject_in_scope(subject, role, scope)

        mock_send.assert_called_once()
        event_data = mock_send.call_args.kwargs["role_assignment"]
        self.assertEqual(
            event_data.actor_id,
            99,
            "actor_id must equal the current user's id when called within a web request",
        )

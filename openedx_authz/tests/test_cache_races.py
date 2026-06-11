"""
Concurrency / cache-race tests for the engine.

Tests four risk areas:

    Group 1 - Cache invalidation round-trip
        assign / unassign -> PolicyCacheControl version bumped -> stale
        _last_policy_loaded_version triggers reload on next get_enforcer().

    Group 2 - Stale-allow window
        A separate SyncedEnforcer instance (simulating a second Django worker)
        retains stale grants after revocation until it calls load_policy().

    Group 3 - In-memory / DB divergence after assign rollback
        When assign_role_to_subject_in_scope() rolls back via transaction.atomic()
        the Casbin in-memory model has already been updated but the cache version
        is never bumped.  Subsequent is_user_allowed() calls return True even
        though the DB has no grant.

    Group 4 - Concurrent enforcement
        SyncedEnforcer.enforce() is safe under concurrent read load and concurrent
        in-memory writes.
"""

import threading
from unittest.mock import patch
from uuid import uuid4

import casbin
from casbin.util import key_match_func
from casbin_adapter.models import CasbinRule
from django.db import IntegrityError

from openedx_authz.api.data import ActionData, ContentLibraryData, RoleData, UserData
from openedx_authz.api.users import (
    assign_role_to_user_in_scope,
    is_user_allowed,
    unassign_role_from_user,
)
from openedx_authz.engine.adapter import ExtendedAdapter
from openedx_authz.engine.enforcer import AuthzEnforcer
from openedx_authz.models import ExtendedCasbinRule
from openedx_authz.models.engine import PolicyCacheControl
from openedx_authz.tests.api.test_roles import BaseRolesTestCase

P_USER = "alice"
LIB_SCOPE = "lib:OrgA:LibX"
LIB_ROLE = "library_admin"
LIB_PERM = "content_libraries.view_library_team"


def _make_independent_enforcer() -> casbin.SyncedEnforcer:
    """
    Create a separate SyncedEnforcer on the same DB, simulating a second process.

    The returned enforcer is loaded with the current DB state at construction.
    Policy changes made via the main AuthzEnforcer singleton are NOT reflected
    in this enforcer until its load_policy() is called explicitly - this is
    exactly the stale-allow window that exists in multi-worker deployments.
    """
    from importlib.resources import files  # pylint: disable=import-outside-toplevel

    model_path = str(files("openedx_authz.engine").joinpath("config/model.conf"))
    adapter = ExtendedAdapter()
    second = casbin.SyncedEnforcer(model_path, adapter)
    # Register a no-op staff bypass so enforcement depends purely on the
    # grouping policy, not on Django User.is_staff / is_superuser.
    second.add_function("is_staff_or_superuser", lambda *_: False)
    second.add_named_domain_matching_func("g", key_match_func)
    # ExtendedAdapter.is_filtered() == True, so Casbin's init_with_model_and_adapter
    # skips the automatic load_policy() call. We must load explicitly.
    second.load_policy()
    return second


# Group 1: Cache invalidation round-trip
class TestCacheInvalidationRoundTrip(BaseRolesTestCase):
    """Verify the PolicyCacheControl version-bump and reload protocol."""

    def _version(self):
        return PolicyCacheControl.get_version()

    def test_assign_bumps_cache_version(self):
        before = self._version()
        assign_role_to_user_in_scope(P_USER, LIB_ROLE, LIB_SCOPE)
        self.assertNotEqual(self._version(), before, "assign must bump the PolicyCacheControl version")

    def test_unassign_bumps_cache_version(self):
        assign_role_to_user_in_scope(P_USER, LIB_ROLE, LIB_SCOPE)
        before = self._version()
        unassign_role_from_user(P_USER, LIB_ROLE, LIB_SCOPE)
        self.assertNotEqual(self._version(), before, "unassign must bump the PolicyCacheControl version")

    def test_stale_version_triggers_reload_on_get_enforcer(self):
        assign_role_to_user_in_scope(P_USER, LIB_ROLE, LIB_SCOPE)
        current_db_version = self._version()

        # Simulate a "stale" process: _last_policy_loaded_version is behind the DB.
        AuthzEnforcer._last_policy_loaded_version = uuid4()  # pylint: disable=protected-access
        self.assertNotEqual(
            AuthzEnforcer._last_policy_loaded_version,
            current_db_version,  # pylint: disable=protected-access
        )

        # get_enforcer() detects the mismatch and reloads.
        AuthzEnforcer.get_enforcer()

        self.assertEqual(
            AuthzEnforcer._last_policy_loaded_version,  # pylint: disable=protected-access
            current_db_version,
            "After reload, _last_policy_loaded_version must match the DB version",
        )

    def test_revocation_reflected_after_forced_reload(self):
        assign_role_to_user_in_scope(P_USER, LIB_ROLE, LIB_SCOPE)
        self.assertTrue(is_user_allowed(P_USER, LIB_PERM, LIB_SCOPE))

        unassign_role_from_user(P_USER, LIB_ROLE, LIB_SCOPE)

        # Force a full reload by clearing the cached version.
        AuthzEnforcer._last_policy_loaded_version = None  # pylint: disable=protected-access
        AuthzEnforcer.get_enforcer()

        self.assertFalse(
            is_user_allowed(P_USER, LIB_PERM, LIB_SCOPE),
            "After reload, a revoked user must be denied",
        )


# Group 2: Stale-allow window
class TestStaleAllowWindow(BaseRolesTestCase):
    """
    Demonstrate the stale-allow window that exists between revocation
    and the next load_policy() call on a second-process enforcer.
    """

    def test_same_process_revocation_is_immediate(self):
        """
        Revocation in the same process takes effect immediately (no stale window).
        """
        assign_role_to_user_in_scope(P_USER, LIB_ROLE, LIB_SCOPE)
        self.assertTrue(is_user_allowed(P_USER, LIB_PERM, LIB_SCOPE))

        unassign_role_from_user(P_USER, LIB_ROLE, LIB_SCOPE)

        self.assertFalse(
            is_user_allowed(P_USER, LIB_PERM, LIB_SCOPE),
            "Same-process revocation must be reflected immediately",
        )

    def test_stale_secondary_enforcer_allows_after_revocation(self):
        """
        A second-process enforcer retains its stale grant after revocation.
        """
        assign_role_to_user_in_scope(P_USER, LIB_ROLE, LIB_SCOPE)

        # "Process B" loads policy - sees the grant.
        second = _make_independent_enforcer()
        user_nk = UserData(external_key=P_USER).namespaced_key
        action_nk = ActionData(external_key=LIB_PERM).namespaced_key
        scope_nk = ContentLibraryData(external_key=LIB_SCOPE).namespaced_key

        self.assertTrue(second.enforce(user_nk, action_nk, scope_nk))

        # "Process A" revokes the role.
        unassign_role_from_user(P_USER, LIB_ROLE, LIB_SCOPE)

        # Process A: immediately denied.
        self.assertFalse(is_user_allowed(P_USER, LIB_PERM, LIB_SCOPE))

        # Process B: still allows - this is the stale-allow window.
        self.assertTrue(
            second.enforce(user_nk, action_nk, scope_nk),
            "Stale-allow window: second-process enforcer must still allow "
            "after revocation until it calls load_policy().",
        )

    def test_stale_secondary_enforcer_corrects_after_load_policy(self):
        """
        The stale-allow window closes as soon as the second enforcer reloads.
        """
        assign_role_to_user_in_scope(P_USER, LIB_ROLE, LIB_SCOPE)
        second = _make_independent_enforcer()
        user_nk = UserData(external_key=P_USER).namespaced_key
        action_nk = ActionData(external_key=LIB_PERM).namespaced_key
        scope_nk = ContentLibraryData(external_key=LIB_SCOPE).namespaced_key

        unassign_role_from_user(P_USER, LIB_ROLE, LIB_SCOPE)
        self.assertTrue(second.enforce(user_nk, action_nk, scope_nk))  # still stale

        second.load_policy()  # simulates the next request on Process B

        self.assertFalse(
            second.enforce(user_nk, action_nk, scope_nk),
            "After load_policy(), the second-process enforcer must reflect the revocation",
        )


# Group 3: In-memory / DB divergence after assign rollback
class TestAssignRollbackDivergence(BaseRolesTestCase):
    """
    assign_role_to_subject_in_scope() updates the Casbin in-memory model
    before the enclosing transaction.atomic() block commits.  When the block is
    rolled back (e.g., because ExtendedCasbinRule.create_based_on_policy fails),
    the DB write is reversed but the in-memory model is not.  Because
    invalidate_policy_cache() is never called, the version numbers still match,
    so the next get_enforcer() call does NOT trigger a reload.  The result:
    is_user_allowed() returns True for an assignment that never landed in the DB.

    This test should flip to make sure this doesn't happen once the bug is fixed.
    """

    def _failing_assign(self):
        """
        Call assign_role_to_user_in_scope with create_based_on_policy mocked to fail.
        """
        with patch.object(
            ExtendedCasbinRule,
            "create_based_on_policy",
            side_effect=IntegrityError("forced rollback (test)"),
        ):
            with self.assertRaises(Exception):
                assign_role_to_user_in_scope(P_USER, LIB_ROLE, LIB_SCOPE)

    def test_failed_assign_produces_stale_in_memory_grant(self):
        """
        After a rolled-back assign, the enforcer in-memory model has the grant
        but the DB does not, and the cache version is unchanged.
        """
        pre_version = PolicyCacheControl.get_version()
        self._failing_assign()

        user_nk = UserData(external_key=P_USER).namespaced_key
        role_nk = RoleData(external_key=LIB_ROLE).namespaced_key
        scope_nk = ContentLibraryData(external_key=LIB_SCOPE).namespaced_key
        enforcer = AuthzEnforcer.get_enforcer()

        # In-memory model was updated before the rollback and was NOT reverted.
        in_memory_roles = enforcer.get_roles_for_user_in_domain(user_nk, scope_nk)
        self.assertIn(
            role_nk,
            in_memory_roles,
            "In-memory enforcer must contain the stale grant after rollback unless this bug is fixed",
        )

        # The DB row was rolled back with the savepoint.
        db_row = CasbinRule.objects.filter(v0=user_nk, v1=role_nk, v2=scope_nk).first()
        self.assertIsNone(
            db_row,
            "DB must have no casbin_rule for the rolled-back assignment",
        )

        # invalidate_policy_cache() was never called, so the version is unchanged.
        self.assertEqual(
            PolicyCacheControl.get_version(),
            pre_version,
            "Cache version must be unchanged after a rolled-back assign",
        )

    def test_stale_grant_exploitable_via_is_user_allowed(self):
        """
        is_user_allowed() returns True due to the stale in-memory grant.

        get_enforcer() -> load_policy_if_needed() sees matching versions -> no reload
        -> uses stale in-memory model -> True even though the DB has no grant.
        """
        self._failing_assign()

        self.assertTrue(
            is_user_allowed(P_USER, LIB_PERM, LIB_SCOPE),
            "is_user_allowed must return True (stale in-memory grant) "
            "even though the DB has no grant for this user, unless this bug is fixed",
        )

    def test_manual_cache_invalidation_closes_stale_grant(self):
        """
        Calling invalidate_policy_cache() followed by get_enforcer() reloads
        from DB and closes the stale grant, restoring correct enforcement.
        """
        self._failing_assign()
        self.assertTrue(is_user_allowed(P_USER, LIB_PERM, LIB_SCOPE))  # stale active

        # Workaround: manually bump the version -> next get_enforcer() reloads.
        AuthzEnforcer.invalidate_policy_cache()
        AuthzEnforcer.get_enforcer()  # triggers load_policy() from DB

        self.assertFalse(
            is_user_allowed(P_USER, LIB_PERM, LIB_SCOPE),
            "After manual invalidation + reload, access must be denied",
        )

    def test_successful_assign_has_no_divergence(self):
        """
        Control: a successful assign keeps DB and in-memory in sync.
        """
        assign_role_to_user_in_scope(P_USER, LIB_ROLE, LIB_SCOPE)

        user_nk = UserData(external_key=P_USER).namespaced_key
        role_nk = RoleData(external_key=LIB_ROLE).namespaced_key
        scope_nk = ContentLibraryData(external_key=LIB_SCOPE).namespaced_key
        enforcer = AuthzEnforcer.get_enforcer()

        in_memory_roles = enforcer.get_roles_for_user_in_domain(user_nk, scope_nk)
        self.assertIn(role_nk, in_memory_roles)

        db_row = CasbinRule.objects.filter(v0=user_nk, v1=role_nk, v2=scope_nk).first()
        self.assertIsNotNone(db_row, "Successful assign must persist to DB")

        self.assertTrue(is_user_allowed(P_USER, LIB_PERM, LIB_SCOPE))


# Group 4: Concurrent enforcement


class TestConcurrentEnforcement(BaseRolesTestCase):
    """
    Verify that SyncedEnforcer.enforce() is safe under concurrent load.

    All tests exercise the in-memory model only (auto_save=False during
    writes) to avoid SQLite "database is locked" errors that arise from
    concurrent writes in a single-process test environment.  In a
    production deployment, concurrent writes are handled by row-level
    locking in the DB.
    """

    def test_concurrent_read_enforcement_does_not_raise(self):
        """
        N threads calling enforcer.enforce() concurrently must not raise.
        """
        assign_role_to_user_in_scope(P_USER, LIB_ROLE, LIB_SCOPE)

        user_nk = UserData(external_key=P_USER).namespaced_key
        action_nk = ActionData(external_key=LIB_PERM).namespaced_key
        scope_nk = ContentLibraryData(external_key=LIB_SCOPE).namespaced_key
        enforcer = AuthzEnforcer.get_enforcer()

        errors: list = []
        results: list = []

        def reader():
            try:
                for _ in range(20):
                    results.append(enforcer.enforce(user_nk, action_nk, scope_nk))
            except Exception as exc:  # pylint: disable=broad-exception-caught
                errors.append(exc)

        threads = [threading.Thread(target=reader) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(errors, [], f"Unexpected thread exceptions: {errors}")
        self.assertEqual(len(results), 200, "All 10×20 enforce() calls must complete")
        self.assertTrue(all(results), "All enforce() calls must return True")

    def test_concurrent_write_and_read_enforcement_does_not_corrupt(self):
        """
        Interleaved in-memory writes and reads must not corrupt the model.

        auto_save is disabled during this test to keep DB writes off the
        critical path and avoid SQLite lock contention.
        """
        assign_role_to_user_in_scope(P_USER, LIB_ROLE, LIB_SCOPE)

        user_nk = UserData(external_key=P_USER).namespaced_key
        role_nk = RoleData(external_key=LIB_ROLE).namespaced_key
        action_nk = ActionData(external_key=LIB_PERM).namespaced_key
        scope_nk = ContentLibraryData(external_key=LIB_SCOPE).namespaced_key
        enforcer = AuthzEnforcer.get_enforcer()

        enforcer.enable_auto_save(False)

        errors: list = []

        def reader():
            try:
                for _ in range(50):
                    enforcer.enforce(user_nk, action_nk, scope_nk)
            except Exception as exc:  # pylint: disable=broad-exception-caught
                errors.append(exc)

        def writer():
            try:
                for _ in range(10):
                    enforcer.add_role_for_user_in_domain(user_nk, role_nk, scope_nk)
                    enforcer.delete_roles_for_user_in_domain(user_nk, role_nk, scope_nk)
            except Exception as exc:  # pylint: disable=broad-exception-caught
                errors.append(exc)

        threads = [threading.Thread(target=reader) for _ in range(8)]
        threads.append(threading.Thread(target=writer))
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        enforcer.enable_auto_save(True)

        self.assertEqual(errors, [], f"Unexpected thread exceptions: {errors}")

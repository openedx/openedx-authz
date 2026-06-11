"""
This test module exercises authorization semantics that should hold for
*any* input, not just for the existing usages already covered by the
``test_enforcement.py`` suite.

Properties tested:

A. **g2 action-grouping graph has no inversions**: Walking every
   ``g2, granted, implied`` row in ``authz.policy``, no chain ever maps a
   strictly-less-privileged action (one held by every role that holds the
   left-hand action) to a more-privileged action.

B. **Cross-namespace isolation**: A role assignment in one scope namespace
   (e.g. ``lib^…``) never grants access to a request in a different
   namespace (e.g. ``course-v1^…``). Exercised with Hypothesis over
   random scope strings.

C. **Unassigned-user deny-by-default**: A user with zero role assignments
   in the enforcer must be denied every ``(action, scope)`` pair.
   Exercised with Hypothesis.

D. **Staff/superuser auto-bypass is scoped**: The
   ``is_admin_or_superuser_check`` matcher function returns True only for
   the documented ``SCOPES_WITH_ADMIN_OR_SUPERUSER_CHECK`` set. For any
   scope outside that set, staff and superusers must not automatically
   pass enforcement.

E. **No bare-``*`` role-assignment domain via the public API**:
   ``assign_role_to_subject_in_scope(scope=ScopeData(external_key="*"))``
   produces a row with domain ``global^*``, not bare ``*``. This keeps
   malformed rows from leaking grant rights through the matcher's
   ``g(r.sub, p.sub, "*")`` global path.

These tests run against an in-memory ``casbin.Enforcer`` loaded from the
real ``model.conf`` and ``authz.policy`` files, against the Django-backed
adapter.
"""

import re
from collections import defaultdict
from importlib.resources import files
from unittest import TestCase

import casbin
import pytest
from casbin.util import key_match_func
from django.contrib.auth import get_user_model
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from openedx_authz.api.data import (
    ContentLibraryData,
    CourseOverviewData,
    OrgContentLibraryGlobData,
    OrgCourseOverviewGlobData,
    PlatformCourseOverviewGlobData,
    RoleData,
    ScopeData,
    UserData,
)
from openedx_authz.api.roles import assign_role_to_subject_in_scope
from openedx_authz.constants import roles as role_constants
from openedx_authz.engine.enforcer import AuthzEnforcer
from openedx_authz.engine.matcher import (
    SCOPES_WITH_ADMIN_OR_SUPERUSER_CHECK,
    is_admin_or_superuser_check,
)
from openedx_authz.tests.api.test_roles import BaseRolesTestCase

User = get_user_model()


POLICY_PATH = str(files("openedx_authz.engine").joinpath("config/authz.policy"))
MODEL_PATH = str(files("openedx_authz.engine").joinpath("config/model.conf"))

# Pattern that strips the "act^" namespace prefix from a Casbin action key.
_ACT_PREFIX = re.compile(r"^act\^")


def _parse_policy_file(
    path: str = POLICY_PATH,
) -> tuple[
    list[tuple[str, str, str, str]],  # p rows
    list[tuple[str, str]],  # g2 rows
]:
    """
    Parse the ``authz.policy`` text file into raw ``p`` and ``g2`` rows.

    Returns:
        (policies, action_grouping):
            - policies: list of (role_key, action_key, scope_key, effect).
            - action_grouping: list of (granted_action_key, implied_action_key).
    """
    policies: list[tuple[str, str, str, str]] = []
    action_grouping: list[tuple[str, str]] = []
    with open(path, encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = [p.strip() for p in line.split(",")]
            if parts[0] == "p" and len(parts) >= 5:
                policies.append((parts[1], parts[2], parts[3], parts[4]))
            elif parts[0] == "g2" and len(parts) >= 3:
                action_grouping.append((parts[1], parts[2]))
    return policies, action_grouping


def _build_in_memory_enforcer(*, stub_staff_bypass: bool = True) -> casbin.Enforcer:
    """
    Build a fresh in-memory enforcer wired up like the production one.

    Uses the real ``model.conf`` and ``authz.policy``, plus the same
    domain-matching function (``key_match_func``) that production uses.

    Args:
        stub_staff_bypass: If True (default), the ``is_staff_or_superuser``
            matcher function is replaced with a no-op that always returns
            False. This isolates matcher-graph tests from the DB -
            otherwise every enforcement call would hit the User table
            and require ``@pytest.mark.django_db``. Set to False to
            exercise the real staff-bypass function (requires DB and
            a populated ``User`` table).
    """
    enf = casbin.Enforcer(MODEL_PATH, POLICY_PATH)
    if stub_staff_bypass:
        enf.add_function("is_staff_or_superuser", lambda *_args: False)
    else:
        enf.add_function("is_staff_or_superuser", is_admin_or_superuser_check)
    enf.add_named_domain_matching_func("g", key_match_func)
    return enf


class TestG2GraphHasNoInversions(TestCase):
    """
    Invariant A: every ``g2, granted, implied`` row points strictly
    "downward" in the privilege tree induced by the role policies.

    Definition of the tree:
        For each action ``A`` that appears as the action of some ``p``
        row, ``support(A)`` is the set of roles whose policy explicitly
        grants ``A``. Action ``X`` is *strictly higher* than action ``Y``
        only if every role that has ``X`` also has ``Y``, but some role
        has ``Y`` without ``X``.

    Invariant: for every ``g2, granted, implied`` row, ``implied`` must
    not be strictly *higher* than ``granted``. Otherwise we'd be giving
    holders of a low-tier action implicit access to a high-tier action.

    This audit catches the most likely class of g2 bug: someone
    accidentally writes ``g2, view_X, manage_X`` (view -> manage), which
    inverts the intended ``manage -> view`` direction.
    """

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.policies, cls.action_grouping = _parse_policy_file()
        cls.role_to_actions: dict[str, set[str]] = defaultdict(set)
        cls.action_to_roles: dict[str, set[str]] = defaultdict(set)
        for role, action, _scope, effect in cls.policies:
            if effect != "allow":
                continue
            cls.role_to_actions[role].add(action)
            cls.action_to_roles[action].add(role)

    def _is_strictly_higher(self, x: str, y: str) -> bool:
        """
        True only if ``x`` is held by strictly fewer roles than ``y``, and
        every role holding ``x`` also holds ``y``.

        In other words, "x is higher-privilege than y in the role tree". Fewer roles have
        x, and every one of them also has y.

        Examples:
            - ``_is_strictly_higher(delete_library, edit_library_content)`` → True
              (only library_admin has delete; admin/author/contributor all have edit).
            - ``_is_strictly_higher(edit_library_content, delete_library)`` → False.
            - ``_is_strictly_higher(view_library, view_library)`` → False (equal supports).
        """
        sx = self.action_to_roles.get(x, set())
        sy = self.action_to_roles.get(y, set())
        return sx.issubset(sy) and sx != sy

    def test_g2_chain_directions(self):
        """
        No ``g2, granted, implied`` row has ``implied`` strictly higher than ``granted``.

        If a role explicitly grants ``granted``, it must also (already) grant ``implied``
        directly - otherwise the g2 chain is silently widening the role's permissions in a
        way the policy author may not have intended.
        """
        violations: list[tuple[str, str, set[str]]] = []
        for granted, implied in self.action_grouping:
            holders_of_granted = self.action_to_roles.get(granted, set())
            holders_of_implied = self.action_to_roles.get(implied, set())
            missing = holders_of_granted - holders_of_implied
            if missing:
                # There exists a role that has `granted` explicitly but
                # NOT `implied` explicitly. The g2 chain therefore
                # widens that role's effective permissions.
                violations.append((granted, implied, missing))

        # Some "widening" rows are intentional ("delete_library implies
        # edit_library_content" - a role that has delete but not edit explicitly
        # will now get edit implicitly, which may or may not be desired). Surface them
        # here.
        if violations:
            msg_lines = [
                "Found g2 rows that widen a role's effective permissions:",
                "(each line: <granted> -> <implied>; roles that have <granted> but not <implied> explicitly)",
            ]
            for granted, implied, roles_widened in violations:
                msg_lines.append(
                    f"  {_ACT_PREFIX.sub('', granted)} -> {_ACT_PREFIX.sub('', implied)}: "
                    f"{sorted(_strip_role(r) for r in roles_widened)}"
                )

            self.assertFalse(violations, "\n\n".join(msg_lines))

        # Hard invariant: no inverted direction. An inversion is a g2 row
        # ``g2, granted, implied`` where ``implied`` is strictly *higher*
        # in the support tree than ``granted`` - i.e., every role that
        # has ``implied`` also has ``granted`` AND some role has ``granted``
        # without ``implied``. That would mean a low-privilege action
        # implicitly confers a high-privilege one.
        #
        # Concretely: a row like ``g2, view_library, delete_library`` would
        # invert because every role that explicitly has ``delete_library``
        # also has ``view_library``, but ``view_library`` is held by many
        # more roles - so ``view_library -> delete_library`` would silently
        # promote everyone with view rights to delete rights.
        inversions = [
            (granted, implied)
            for granted, implied in self.action_grouping
            if self._is_strictly_higher(implied, granted)
        ]
        self.assertFalse(
            inversions,
            msg=(
                "g2 row(s) are inverted (implied action is strictly higher in "
                "the support tree than granted): "
                + ", ".join(f"{_ACT_PREFIX.sub('', g)} -> {_ACT_PREFIX.sub('', i)}" for g, i in inversions)
            ),
        )

    def test_g2_has_no_cycles(self):
        """
        The ``g2`` graph is a DAG. Cycles would create unbounded
        permission grants and is probably a typo.

        This is just a depth-first cycle detection test. Nodes
        marked WHITE are unvisited, GRAY are currently being visited
        (if you find a GRAY node while traversing, you have a cycle),
        and BLACK have been visited and have no cycles. All nodes
        should be marked BLACK at the end.
        """
        adj: dict[str, set[str]] = defaultdict(set)
        for granted, implied in self.action_grouping:
            adj[granted].add(implied)

        WHITE, GRAY, BLACK = 0, 1, 2
        color: dict[str, int] = defaultdict(lambda: WHITE)
        cycle_path: list[str] = []

        def visit(node: str, path: list[str]) -> bool:
            color[node] = GRAY
            path.append(node)
            for nbr in adj.get(node, ()):
                if color[nbr] == GRAY:
                    cycle_path.extend(path[path.index(nbr) :])
                    cycle_path.append(nbr)
                    return True
                if color[nbr] == WHITE and visit(nbr, path):
                    return True
            path.pop()
            color[node] = BLACK
            return False

        for n in list(adj.keys()):
            if color[n] == WHITE and visit(n, []):
                break

        self.assertFalse(
            cycle_path,
            msg=("g2 graph contains a cycle: " + " → ".join(_ACT_PREFIX.sub("", n) for n in cycle_path)),
        )


def _strip_role(role_key: str) -> str:
    """role^foo → foo, for nicer test output."""
    return role_key.split("^", 1)[-1] if "^" in role_key else role_key


# Hand-crafted strategy for valid-shaped scope external keys per namespace.
# We don't need full coverage of opaque-keys formats - we just need scope
# strings that *parse* as their intended namespace, so the matcher can be
# exercised cleanly.

# Use a small, fixed alphabet so the LMS validators don't reject our
# generated keys. Org / slug / course-run names in practice are
# `[A-Za-z0-9_.-]+`.
_KEY_ALPHA = st.text(
    alphabet=st.characters(
        whitelist_categories=("Lu", "Ll", "Nd"),
        whitelist_characters="_.-",
    ),
    min_size=1,
    max_size=8,
)


@st.composite
def _library_scope(draw) -> str:
    return f"lib:{draw(_KEY_ALPHA)}:{draw(_KEY_ALPHA)}"


@st.composite
def _course_scope(draw) -> str:
    return f"course-v1:{draw(_KEY_ALPHA)}+{draw(_KEY_ALPHA)}+{draw(_KEY_ALPHA)}"


_LIBRARY_ACTIONS = [
    "content_libraries.view_library",
    "content_libraries.edit_library_content",
    "content_libraries.delete_library",
    "content_libraries.manage_library_team",
]

_COURSE_ACTIONS = [
    "courses.view_course",
    "courses.edit_course_content",
    "courses.publish_course_content",
    "courses.manage_course_team",
]


class TestCrossNamespaceIsolation(TestCase):
    """
    A role assigned in one namespace must not grant access in any other
    namespace.

    Concretely: assigning ``library_admin`` to a user on ``lib:Org1:LIB1``
    must not make ``is_user_allowed(user, courses.view_course,
    course-v1:Org1+C+R)`` return True, and vice-versa.

    Uses Hypothesis to generate random library and course scope strings.
    Each example creates a fresh in-memory enforcer (cheap), assigns one
    role in one namespace, and probes the matcher with actions in the
    *other* namespace.
    """

    def _enforcer_with(self, subject_key: str, role_key: str, scope_key: str) -> casbin.Enforcer:
        """
        Fresh enforcer with one role assignment baked in.
        """
        enf = _build_in_memory_enforcer()
        enf.add_grouping_policy(subject_key, role_key, scope_key)
        return enf

    @settings(
        max_examples=50,
    )
    @given(lib_external_key=_library_scope(), course_external_key=_course_scope())
    def test_library_role_does_not_grant_course_action(self, lib_external_key: str, course_external_key: str):
        """
        library_admin assigned never grants a course action on any course scope.
        """
        enf = self._enforcer_with(
            subject_key="user^alice",
            role_key=f"role^{role_constants.LIBRARY_ADMIN.external_key}",
            scope_key=f"lib^{lib_external_key}",
        )
        for action in _COURSE_ACTIONS:
            allowed = enf.enforce("user^alice", f"act^{action}", f"course-v1^{course_external_key}")
            self.assertFalse(
                allowed,
                msg=(
                    f"Cross-namespace leak: library_admin on lib^{lib_external_key} "
                    f"granted course action {action} on course-v1^{course_external_key}"
                ),
            )

    @settings(
        max_examples=50,
    )
    @given(course_external_key=_course_scope(), lib_external_key=_library_scope())
    def test_course_role_does_not_grant_library_action(self, course_external_key: str, lib_external_key: str):
        """
        course_admin never grants a library action on any library scope.
        """
        enf = self._enforcer_with(
            subject_key="user^bob",
            role_key=f"role^{role_constants.COURSE_ADMIN.external_key}",
            scope_key=f"course-v1^{course_external_key}",
        )
        for action in _LIBRARY_ACTIONS:
            allowed = enf.enforce("user^bob", f"act^{action}", f"lib^{lib_external_key}")
            self.assertFalse(
                allowed,
                msg=(
                    f"Cross-namespace leak: course_admin on course-v1^{course_external_key} "
                    f"granted library action {action} on lib^{lib_external_key}"
                ),
            )

    def test_org_glob_does_not_cross_namespaces(self):
        """
        An org-level glob assignment stays within its namespace.

        Not Hypothesis-fuzzed because the keyMatch semantics
        of org-globs are already pinned by ``test_enforcement.py``.
        """
        enf = self._enforcer_with(
            subject_key="user^carol",
            role_key=f"role^{role_constants.LIBRARY_ADMIN.external_key}",
            scope_key="lib^lib:OrgA:*",  # org-wide library glob
        )
        # Library access within OrgA: allowed.
        self.assertTrue(
            enf.enforce(
                "user^carol",
                "act^content_libraries.view_library",
                "lib^lib:OrgA:LibX",
            ),
            msg="Sanity check: library_admin on lib:OrgA:* should view lib:OrgA:LibX",
        )
        # Course access in OrgA: must be denied.
        self.assertFalse(
            enf.enforce(
                "user^carol",
                "act^courses.view_course",
                "course-v1^course-v1:OrgA+C+R",
            ),
            msg=("Cross-namespace leak: lib:OrgA:* granted access to course-v1:OrgA+C+R"),
        )


class TestUnassignedUserAlwaysDenied(TestCase):
    """
    A user with zero role assignments is denied every ``(action, scope)``.

    Verifies the Casbin default remains and works. Checks with random
    inputs so any future regression like a stray ``g, *, role^admin, *``
    row sneaking into ``authz.policy`` fails here instead of escalating
    silently.
    """

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.enforcer = _build_in_memory_enforcer()

    @settings(
        max_examples=100,
    )
    @given(
        action=st.sampled_from(_LIBRARY_ACTIONS + _COURSE_ACTIONS),
        scope=st.one_of(_library_scope(), _course_scope()),
    )
    def test_unassigned_user_denied(self, action: str, scope: str):
        """A user that the enforcer has never heard of must be denied."""
        subject = "user^00000000-no-such-user"
        ns_prefix = "lib^" if scope.startswith("lib:") else "course-v1^"
        allowed = self.enforcer.enforce(subject, f"act^{action}", f"{ns_prefix}{scope}")
        self.assertFalse(
            allowed,
            msg=(f"Deny-by-default violated: unassigned subject {subject} was granted {action} on {ns_prefix}{scope}"),
        )


class TestStaffSuperuserBypassIsScopedToDocumentedTypes(TestCase):
    """
    ``is_admin_or_superuser_check`` returns True only for scopes whose
    ``(NAMESPACE, type)`` tuple is in
    ``SCOPES_WITH_ADMIN_OR_SUPERUSER_CHECK``.

    This pins the matcher-side behavior independent of the REST permission
    classes' own staff/superuser bypass. If a new scope subclass is
    introduced that should bypass for staff, the maintainer must
    explicitly add it to ``SCOPES_WITH_ADMIN_OR_SUPERUSER_CHECK`` -
    otherwise this test catches the omission.
    """

    EXPECTED_BYPASS_TYPES: frozenset = frozenset(
        {
            ContentLibraryData,
            CourseOverviewData,
            OrgContentLibraryGlobData,
            OrgCourseOverviewGlobData,
            PlatformCourseOverviewGlobData,
        }
    )

    def test_documented_set_matches_expectation(self):
        """
        The matcher's set of bypass scopes matches our documented list.

        If the set in ``engine/matcher.py`` is changed this test fails
        and forces a security review of the change.
        """
        types_in_set = {type_ for (_ns, type_) in SCOPES_WITH_ADMIN_OR_SUPERUSER_CHECK}
        self.assertEqual(
            types_in_set,
            self.EXPECTED_BYPASS_TYPES,
            msg=(
                "Staff/superuser bypass set changed. Review carefully - "
                "this affects who gets automatic access to which scopes."
            ),
        )

    def test_base_scopedata_is_not_in_bypass_set(self):
        """
        The base ``ScopeData`` class must NOT be in the bypass set.

        Otherwise a malformed ``global^*`` assignment would gain
        matcher-level bypass for any staff user which we're explicitly
        not supporting yet.
        """
        types_in_set = {type_ for (_ns, type_) in SCOPES_WITH_ADMIN_OR_SUPERUSER_CHECK}
        self.assertNotIn(ScopeData, types_in_set)


@pytest.mark.django_db
class TestStaffSuperuserBypassFunctionBehavior(BaseRolesTestCase):
    """
    Actually call ``is_admin_or_superuser_check`` with a real (stub)
    staff user and confirm it returns True only for the documented
    scope subclasses.
    """

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        # is_staff=True flips the bypass in the documented scopes.
        User.objects.get_or_create(
            username="phase2_staff",
            defaults={
                "email": "phase2_staff@example.com",
                "is_staff": True,
                "is_superuser": False,
            },
        )
        User.objects.get_or_create(
            username="phase2_regular",
            defaults={"email": "phase2_regular@example.com"},
        )

    def test_staff_bypass_fires_for_library_and_course_scopes(self):
        """Staff users get auto-True for ContentLibrary and CourseOverview scopes."""
        for scope_key in (
            "lib^lib:OrgA:LibX",
            "course-v1^course-v1:OrgA+C+R",
            "lib^lib:OrgA:*",
            "course-v1^course-v1:OrgA+*",
            "course-v1^course-v1:*",
        ):
            with self.subTest(scope=scope_key):
                self.assertTrue(
                    is_admin_or_superuser_check(
                        "user^phase2_staff",
                        "act^anything",
                        scope_key,
                    ),
                    msg=f"staff was NOT auto-allowed for {scope_key}",
                )

    def test_staff_bypass_does_NOT_fire_for_global_or_unknown_scopes(self):
        """Staff users do NOT get auto-True for scopes outside the documented set.

        This is the property F-001 depends on: a ``global^*`` role
        assignment must not be exercisable via the matcher even by a
        Django staff user. If this test ever flips, F-001 escalates from
        "admin-console DoS" to "any staff user gains all-scope authority
        via a malformed row."
        """
        for scope_key in (
            "global^*",
            "global^arbitrary_global_scope",
            "made-up^anything",
        ):
            with self.subTest(scope=scope_key):
                self.assertFalse(
                    is_admin_or_superuser_check(
                        "user^phase2_staff",
                        "act^anything",
                        scope_key,
                    ),
                    msg=f"staff was unexpectedly auto-allowed for {scope_key}",
                )

    def test_non_staff_never_gets_bypass(self):
        """Regular (non-staff, non-superuser) users never trigger the bypass,
        even on a documented scope type."""
        self.assertFalse(
            is_admin_or_superuser_check(
                "user^phase2_regular",
                "act^anything",
                "lib^lib:OrgA:LibX",
            )
        )

    def test_bypass_handles_unknown_user_gracefully(self):
        """A nonexistent username does not crash the matcher (returns False)."""
        self.assertFalse(
            is_admin_or_superuser_check(
                "user^this-user-does-not-exist",
                "act^anything",
                "lib^lib:OrgA:LibX",
            )
        )


@pytest.mark.django_db
class TestGlobalWildcardAssignmentUsesGlobalCaret(BaseRolesTestCase):
    """
    Confirm that ``assign_role_to_subject_in_scope`` with
    ``ScopeData(external_key="*")`` produces a Casbin row with domain
    ``global^*``, not bare ``*``.

    This matters because the matcher contains a hard-coded
    ``g(r.sub, p.sub, "*")`` global-role check. A bare-``*`` assignment
    domain would short-circuit that check via ``key_match_func("*", "*")
    = True`` and grant the user the role *everywhere*. The namespaced
    ``global^*`` form does not match the literal ``"*"`` second argument
    of ``key_match_func`` and so does not escalate the same way.

    The malformed ``global^*`` row breaks the admin console listing,
    but does not confer any matcher grants. This is just to guard against
    future refactors that might accidentally widen the blast radius.
    """

    def test_global_wildcard_assignment_stored_as_global_caret(self):
        assign_role_to_subject_in_scope(
            subject=UserData(external_key="alice"),
            role=RoleData(external_key=role_constants.LIBRARY_ADMIN.external_key),
            scope=ScopeData(external_key="*"),
        )

        rows = AuthzEnforcer.get_enforcer().get_filtered_grouping_policy(0, "user^alice")
        self.assertEqual(len(rows), 1)
        # Most importantly, it must not be bare "*"
        self.assertNotEqual(rows[0][2], "*")
        # This is what we actually expect
        self.assertEqual(rows[0][2], "global^*")

    def test_global_caret_assignment_does_not_grant_via_matcher_global_path(self):
        """
        Confirm that a ``global^*`` row does not grant access to any
        ContentLibrary scope. If these fail unexpectedly we have a potential
        privilege escalation.
        """
        assign_role_to_subject_in_scope(
            subject=UserData(external_key="alice"),
            role=RoleData(external_key=role_constants.LIBRARY_ADMIN.external_key),
            scope=ScopeData(external_key="*"),
        )

        enforcer = AuthzEnforcer.get_enforcer()
        # library_admin would normally grant view_library on a library
        # scope. With only the global^* assignment, it must not.
        allowed = enforcer.enforce(
            "user^alice",
            "act^content_libraries.view_library",
            "lib^lib:OrgA:LibX",
        )
        self.assertFalse(
            allowed,
            msg=(
                "Potential privilege escalation: a global^* role assignment granted "
                "view_library on a specific library scope!"
            ),
        )

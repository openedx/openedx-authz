"""Unit tests for the Casbin policy boundary (``engine.policy``).

Covers the domain-typed row objects (:class:`PolicyRow`, :class:`GroupingRow`),
the shared :class:`GroupingPolicyIndex` layout they delegate to, and the
:class:`PolicyStore` facade that translates between those typed rows and the raw
``list[str]`` shape the Casbin enforcer stores.

These are pure-Python units with no database access, so they run against a tiny
in-memory fake enforcer rather than the real Casbin stack.
"""

from __future__ import annotations

from unittest import mock

import pytest

from openedx_authz.data import GroupingPolicyIndex
from openedx_authz.engine.policy import GroupingRow, PolicyRow, PolicyStore


class FakeEnforcer:
    """Minimal in-memory stand-in for the Casbin enforcer.

    Stores ``p`` and ``g`` rows as lists of string lists — the shape the real
    enforcer returns and accepts — so the store's translation can be exercised
    without Django or Casbin.
    """

    def __init__(self, policies=None, grouping=None):
        self._policies = [list(row) for row in (policies or [])]
        self._grouping = [list(row) for row in (grouping or [])]

    def get_policy(self) -> list[list[str]]:
        """Return a copy of the stored ``p`` rows."""
        return [list(row) for row in self._policies]

    def get_grouping_policy(self) -> list[list[str]]:
        """Return a copy of the stored ``g`` rows."""
        return [list(row) for row in self._grouping]

    def add_policy(self, *args) -> bool:
        """Add a ``p`` row, ignoring exact duplicates. Returns True if added."""
        row = list(args)
        if row in self._policies:
            return False
        self._policies.append(row)
        return True

    def remove_policy(self, *args) -> bool:
        """Remove a ``p`` row if present. Returns True if removed."""
        row = list(args)
        if row not in self._policies:
            return False
        self._policies.remove(row)
        return True

    def remove_grouping_policy(self, *args) -> bool:
        """Remove a ``g`` row if present. Returns True if removed."""
        row = list(args)
        if row not in self._grouping:
            return False
        self._grouping.remove(row)
        return True


class TestPolicyRow:
    """Constructing and round-tripping a single Casbin ``p`` row."""

    def test_from_policy_round_trips_as_policy(self):
        """A row rebuilt from ``as_policy`` output equals the original."""
        row = PolicyRow("role^course_editor", "act^courses.view_course", "course-v1^*", "allow")
        assert PolicyRow.from_policy(row.as_policy()) == row

    def test_ptype_is_the_fixed_p_constant(self):
        """``PTYPE`` is a class constant, not a per-instance field."""
        assert PolicyRow.PTYPE == "p"

    def test_from_policy_reads_a_stored_row(self):
        """A stored ``[subject, action, scope, effect]`` row maps to its fields."""
        row = PolicyRow.from_policy(["role^r", "act^p", "course-v1^*", "allow"])
        assert (row.subject, row.action, row.scope, row.effect) == ("role^r", "act^p", "course-v1^*", "allow")

    def test_from_policy_pads_short_rows_with_empty_strings(self):
        """A row with fewer than four values is padded rather than raising."""
        row = PolicyRow.from_policy(["role^r", "act^p"])
        assert (row.subject, row.action, row.scope, row.effect) == ("role^r", "act^p", "", "")


class TestGroupingPolicyIndex:
    """The shared ``g`` row field layout, mirroring ``PolicyIndex``."""

    def test_parse_reads_all_three_fields(self):
        """A full ``[subject, role, scope]`` row maps to its named fields."""
        assert GroupingPolicyIndex.parse(["user^alice", "role^editor", "course-v1^*"]) == (
            "user^alice",
            "role^editor",
            "course-v1^*",
        )

    def test_parse_rejects_a_short_row(self):
        """Strict like ``PolicyIndex``: a row shorter than the width is rejected."""
        with pytest.raises(ValueError):
            GroupingPolicyIndex.parse(["user^alice", "role^editor"])

    def test_pad_then_parse_tolerates_a_scope_less_row(self):
        """Padding first lets the strict ``parse`` default the missing scope."""
        padded = GroupingPolicyIndex.pad(["user^alice", "role^editor"])
        assert GroupingPolicyIndex.parse(padded) == ("user^alice", "role^editor", "")

    def test_pad_fills_up_to_required_width(self):
        """Padding brings a short row up to the three-field width."""
        assert GroupingPolicyIndex.pad(["user^alice", "role^editor"]) == ["user^alice", "role^editor", ""]


class TestGroupingRow:
    """Constructing and round-tripping a single Casbin ``g`` row."""

    def test_round_trips_through_as_policy(self):
        """A row rebuilt from ``as_policy`` output equals the original."""
        row = GroupingRow("user^alice", "role^editor", "course-v1^*")
        assert GroupingRow.from_policy(row.as_policy()) == row

    def test_from_policy_reads_a_stored_row(self):
        """A stored ``[subject, role, scope]`` row maps to its fields."""
        row = GroupingRow.from_policy(["user^alice", "role^editor", "course-v1^*"])
        assert (row.subject, row.role, row.scope) == ("user^alice", "role^editor", "course-v1^*")

    def test_from_policy_defaults_missing_scope(self):
        """A scope-less stored row maps to an empty-string scope rather than raising."""
        row = GroupingRow.from_policy(["user^alice", "role^editor"])
        assert (row.subject, row.role, row.scope) == ("user^alice", "role^editor", "")

    def test_is_hashable(self):
        """Grouping rows are usable in sets (frozen dataclass)."""
        row = GroupingRow("user^alice", "role^editor", "course-v1^*")
        assert row in {row}


class TestPolicyStorePolicyRows:
    """``PolicyStore`` translates ``p`` rows to and from :class:`PolicyRow`."""

    def test_get_policy_rows_returns_typed_rows(self):
        """Stored raw ``p`` rows come back as :class:`PolicyRow` objects."""
        enforcer = FakeEnforcer(policies=[["role^editor", "act^courses.view", "course-v1^*", "allow"]])
        store = PolicyStore(enforcer)

        rows = store.get_policy_rows()

        assert rows == [PolicyRow("role^editor", "act^courses.view", "course-v1^*", "allow")]

    def test_add_policy_row_writes_the_raw_shape(self):
        """A typed row is persisted in the enforcer's ``list[str]`` form."""
        enforcer = FakeEnforcer()
        store = PolicyStore(enforcer)
        row = PolicyRow("role^editor", "act^courses.view", "course-v1^*", "allow")

        assert store.add_policy_row(row) is True
        assert enforcer.get_policy() == [["role^editor", "act^courses.view", "course-v1^*", "allow"]]

    def test_add_policy_row_reports_duplicate_as_not_added(self):
        """Re-adding an existing row returns the enforcer's False result."""
        row = PolicyRow("role^editor", "act^courses.view", "course-v1^*", "allow")
        enforcer = FakeEnforcer(policies=[row.as_policy()])
        store = PolicyStore(enforcer)

        assert store.add_policy_row(row) is False

    def test_remove_policy_row_deletes_the_matching_row(self):
        """Removing a typed row deletes its exact raw counterpart."""
        row = PolicyRow("role^editor", "act^courses.view", "course-v1^*", "allow")
        enforcer = FakeEnforcer(policies=[row.as_policy()])
        store = PolicyStore(enforcer)

        assert store.remove_policy_row(row) is True
        assert enforcer.get_policy() == []


class TestPolicyStoreGroupingRows:
    """``PolicyStore`` translates ``g`` rows to and from :class:`GroupingRow`."""

    def test_get_grouping_rows_returns_typed_rows(self):
        """Stored raw ``g`` rows come back as :class:`GroupingRow` objects."""
        enforcer = FakeEnforcer(grouping=[["user^alice", "role^editor", "course-v1^*"]])
        store = PolicyStore(enforcer)

        assert store.get_grouping_rows() == [GroupingRow("user^alice", "role^editor", "course-v1^*")]

    def test_get_grouping_rows_tolerates_scope_less_rows(self):
        """A stored ``[subject, role]`` row maps to an empty-string scope."""
        enforcer = FakeEnforcer(grouping=[["user^alice", "role^editor"]])
        store = PolicyStore(enforcer)

        assert store.get_grouping_rows() == [GroupingRow("user^alice", "role^editor", "")]

    def test_remove_grouping_row_deletes_the_exact_stored_row(self):
        """Removing a typed grouping row deletes its exact raw counterpart."""
        enforcer = FakeEnforcer(grouping=[["user^alice", "role^editor", "course-v1^*"]])
        store = PolicyStore(enforcer)

        assert store.remove_grouping_row(GroupingRow("user^alice", "role^editor", "course-v1^*")) is True
        assert enforcer.get_grouping_policy() == []


class TestPolicyStoreEnforcerResolution:
    """``PolicyStore`` owns enforcer resolution so callers hold no handle."""

    def test_injected_enforcer_is_used_without_resolution(self):
        """A store built with an enforcer never calls ``AuthzEnforcer``."""
        enforcer = FakeEnforcer()
        store = PolicyStore(enforcer)

        with mock.patch("openedx_authz.engine.policy.AuthzEnforcer") as authz_enforcer:
            store.get_policy_rows()
            authz_enforcer.get_enforcer.assert_not_called()

    def test_bare_store_resolves_the_enforcer_lazily_on_first_use(self):
        """A bare ``PolicyStore()`` resolves ``AuthzEnforcer.get_enforcer()`` once, on use."""
        resolved = FakeEnforcer(policies=[["role^editor", "act^courses.view", "course-v1^*", "allow"]])
        store = PolicyStore()

        with mock.patch("openedx_authz.engine.policy.AuthzEnforcer") as authz_enforcer:
            authz_enforcer.get_enforcer.return_value = resolved

            # Not resolved at construction — only when a method is first called.
            authz_enforcer.get_enforcer.assert_not_called()
            first = store.get_policy_rows()
            second = store.get_policy_rows()

        assert first == second == [PolicyRow("role^editor", "act^courses.view", "course-v1^*", "allow")]
        # Cached after the first resolution: one lookup despite two calls.
        authz_enforcer.get_enforcer.assert_called_once_with()

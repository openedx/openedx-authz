"""Unit tests for the permission dependency graph helpers (ADR 0034)."""

import pytest

from openedx_authz.engine.schema.dependencies import all_dependencies, find_cycles, missing_dependencies

# The library dependencies previously declared as g2 rows in authz.policy.
LIBRARY_DEPENDENCIES = {
    "manage_library_tags": ("edit_library_content",),
    "delete_library": ("edit_library_content",),
    "publish_library_content": ("edit_library_content", "view_library"),
    "edit_library_content": ("view_library",),
    "reuse_library_content": ("view_library",),
    "manage_library_team": ("view_library_team",),
    "delete_library_collection": ("edit_library_collection",),
    "create_library_collection": ("edit_library_collection",),
    "edit_library_collection": ("view_library",),
}


class TestAllDependencies:
    """All dependencies include direct and indirect ones."""

    def test_includes_indirect_dependencies(self):
        """``manage_library_tags`` requires ``view_library`` through ``edit_library_content``."""
        assert all_dependencies(["manage_library_tags"], LIBRARY_DEPENDENCIES) == {
            "edit_library_content",
            "view_library",
        }

    def test_permission_without_dependencies_has_none(self):
        """A permission with no ``depends_on`` requires nothing else."""
        assert all_dependencies(["view_library"], LIBRARY_DEPENDENCIES) == set()

    def test_given_permissions_are_not_included(self):
        """The result lists what the given permissions need, not the permissions themselves."""
        assert all_dependencies(["delete_library", "edit_library_content"], LIBRARY_DEPENDENCIES) == {
            "edit_library_content",
            "view_library",
        }
        assert all_dependencies(["edit_library_content"], LIBRARY_DEPENDENCIES) == {"view_library"}

    def test_unknown_dependencies_are_included_but_not_followed(self):
        """A dependency missing from the map is still required, it just has no dependencies of its own."""
        assert all_dependencies(["a"], {"a": ("missing",)}) == {"missing"}

    def test_cycles_terminate(self):
        """A cycle does not loop forever; validation rejects it separately."""
        assert all_dependencies(["a"], {"a": ("b",), "b": ("a",)}) == {"a", "b"}


class TestMissingDependencies:
    """The role rule: a set of permissions must include all of their dependencies."""

    def test_complete_set_has_nothing_missing(self):
        """A set that lists every direct and indirect dependency is complete."""
        granted = ["manage_library_tags", "edit_library_content", "view_library"]

        assert not missing_dependencies(granted, LIBRARY_DEPENDENCIES)

    def test_reports_direct_and_indirect_dependencies_per_permission(self):
        """Each permission maps to every dependency it lacks, sorted."""
        granted = ["manage_library_tags", "reuse_library_content"]

        assert missing_dependencies(granted, LIBRARY_DEPENDENCIES) == {
            "manage_library_tags": ("edit_library_content", "view_library"),
            "reuse_library_content": ("view_library",),
        }

    def test_accepts_any_iterable(self):
        """Callers can pass tuples, sets or generators."""
        assert missing_dependencies(iter(("edit_library_content",)), LIBRARY_DEPENDENCIES)


class TestFindCycles:
    """Cycles are reported once each, starting from the ID that sorts first."""

    def test_acyclic_graph_has_no_cycles(self):
        """The library dependencies form no cycle."""
        assert find_cycles(LIBRARY_DEPENDENCIES) == []

    def test_self_dependency_is_a_cycle_of_one(self):
        """A permission that depends on itself is reported on its own."""
        assert find_cycles({"a": ("a",)}) == [("a",)]

    @pytest.mark.parametrize(
        "graph",
        [
            {"a": ("b",), "b": ("c",), "c": ("a",)},
            {"c": ("a",), "a": ("b",), "b": ("c",)},
        ],
    )
    def test_cycle_starts_at_its_alphabetically_first_id(self, graph):
        """The same cycle starts at the ID that sorts first, whatever the order of the map."""
        assert find_cycles(graph) == [("a", "b", "c")]

    def test_reports_separate_cycles(self):
        """Two unrelated cycles are both reported."""
        graph = {"a": ("b",), "b": ("a",), "x": ("y",), "y": ("x",), "z": ("a",)}

        assert find_cycles(graph) == [("a", "b"), ("x", "y")]

    def test_unknown_dependencies_are_ignored(self):
        """A dependency with no entry in the map is not followed, so it neither raises nor forms a cycle."""
        assert find_cycles({"a": ("missing",)}) == []

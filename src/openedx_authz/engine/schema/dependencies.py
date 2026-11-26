"""Permission dependency graph helpers (ADR 0034).

A permission's ``depends_on`` lists the permissions it directly requires. These
helpers work on a plain mapping of permission ID to its direct dependencies, so
schema validation and the Custom Roles API can apply the same rules to any set
of permissions. ``dependency_map`` must include every permission that has
dependencies: results for a partial map are incomplete, not an error.

No Casbin or Django imports, so it stays unit-testable in isolation.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping

DependencyMap = Mapping[str, Iterable[str]]


def all_dependencies(permission_ids: Iterable[str], dependency_map: DependencyMap) -> set[str]:
    """Return every direct and indirect dependency of the given permissions.

    The result does not include a given permission unless another given permission depends on
    it. A dependency with no entry in ``dependency_map`` is included in the result, but has no
    dependencies of its own to add. Cycles do not loop forever.

    Args:
        permission_ids: Complete permission IDs (e.g., ``["content_libraries.edit_library_content"]``).
        dependency_map: Each permission ID mapped to the IDs of its direct dependencies.

    Returns:
        set[str]: The IDs of the permissions the given ones require, directly or indirectly.
    """
    found: set[str] = set()
    pending = [dependency for permission_id in permission_ids for dependency in dependency_map.get(permission_id, ())]
    while pending:
        dependency = pending.pop()
        if dependency in found:
            continue
        found.add(dependency)
        pending.extend(dependency_map.get(dependency, ()))
    return found


def missing_dependencies(permission_ids: Iterable[str], dependency_map: DependencyMap) -> dict[str, tuple[str, ...]]:
    """Return, for each given permission, the dependencies that are not also given.

    This is the role rule of ADR 0034 §3: a set of permissions is complete when it includes every
    direct and indirect dependency of each of its permissions.

    Args:
        permission_ids: The complete permission IDs a role grants.
        dependency_map: Each permission ID mapped to the IDs of its direct dependencies.

    Returns:
        dict[str, tuple[str, ...]]: Each permission with missing dependencies, mapped to the sorted
        IDs it is missing. Empty when the set is complete. Ordered by permission ID.
    """
    granted = set(permission_ids)
    missing = {}
    for permission_id in sorted(granted):
        absent = all_dependencies((permission_id,), dependency_map) - granted
        if absent:
            missing[permission_id] = tuple(sorted(absent))
    return missing


def find_cycles(dependency_map: DependencyMap) -> list[tuple[str, ...]]:
    """Return dependency cycles among the permissions in ``dependency_map``.

    A permission that depends on itself is a cycle of one. At least one cycle is returned for
    every group of permissions that depend on each other, which is enough to reject the schema and
    point the author at the problem. Dependencies missing from ``dependency_map`` are ignored.

    Args:
        dependency_map: Each permission ID mapped to the IDs of its direct dependencies.

    Returns:
        list[tuple[str, ...]]: Each cycle as the permissions along it, starting from the ID that
        sorts first, with the return to the start left implicit. Sorted and without duplicates.
    """
    graph = {permission_id: sorted(set(dependencies)) for permission_id, dependencies in dependency_map.items()}
    visited: set[str] = set()
    cycles: set[tuple[str, ...]] = set()

    for start in sorted(graph):
        if start in visited:
            continue
        # Iterative depth-first search. ``path`` is the chain from ``start`` to the current
        # permission, and ``position`` finds where a back edge re-enters it.
        path: list[str] = [start]
        position = {start: 0}
        iterators = [iter(graph[start])]
        visited.add(start)
        while iterators:
            dependency = next(iterators[-1], None)
            if dependency is None:
                del position[path.pop()]
                iterators.pop()
                continue
            if dependency not in graph:
                continue
            if dependency in position:
                cycles.add(_canonical(path[position[dependency] :]))
                continue
            if dependency in visited:
                continue
            visited.add(dependency)
            position[dependency] = len(path)
            path.append(dependency)
            iterators.append(iter(graph[dependency]))

    return sorted(cycles)


def _canonical(cycle: list[str]) -> tuple[str, ...]:
    """Rotate a cycle to start at the ID that sorts first, so the same cycle is reported once."""
    start = cycle.index(min(cycle))
    return tuple(cycle[start:] + cycle[:start])

"""
Filter Implementation for Casbin Policy Selection.

This module provides a Filter class used to specify criteria for selective
loading of Casbin policy rules. The Filter class allows for efficient policy
management by enabling the loading of only relevant policy rules based on
policy type and attribute values.

The Filter class is designed to work with the ExtendedAdapter to provide
optimized policy loading in scenarios where only a subset of policies
is needed, such as loading policies for a specific user, course, or role.
"""

from typing import List, Optional

import attr


@attr.define
class Filter:
    """
    Filter class for selective Casbin policy loading.

    This class defines filtering criteria used to load only specific policy rules
    from the database instead of loading all policies. Each attribute corresponds
    to a column in the Casbin policy storage schema and accepts a list of values
    to filter by.

    Attributes:
        ptype (list): Policy type filter.
            * 'p'  → Policy rule (permissions).
            * 'g'  → Grouping rule (user ↔ role).
            * 'g2' → Action grouping (parent action ↔ child action).

        v0 (list): First policy value filter.
            * For 'p' → Subject (e.g., 'role:org_admin', 'user:alice').
            * For 'g' → User (e.g., 'user:alice').
            * For 'g2' → Parent action (e.g., 'act:manage').

        v1 (list): Second policy value filter.
            * For 'p' → Action (e.g., 'act:manage', 'act:edit').
            * For 'g' → Role (e.g., 'role:org_admin').
            * For 'g2' → Child action (e.g., 'act:edit').

        v2 (list): Third policy value filter.
            * For 'p' → Object or resource (e.g., 'lib:*', 'org:MIT').
            * For 'g' → Scope or resource (e.g., 'org:MIT').
            * For 'g2' → Not used.

        v3 (list): Fourth policy value filter.
            * For 'p' → Effect ('allow' or 'deny').
            * Otherwise unused.

        v4 (list): Fifth policy value filter (optional additional context).
        v5 (list): Sixth policy value filter (optional additional context).

    Note:
        - Empty lists for any attribute means no filtering on that attribute
        - Non-empty lists create an "IN" filter for that attribute
        - All non-empty filters are combined with AND logic

    Examples:
        Filter by policy type only:
        ```python
        filter_obj = Filter(ptype=['p'])  # Only load policy rules, not grouping rules
        ```

        Filter by user and course:
        ```python
        filter_obj = Filter(
            v0=['user:student123'],      # Specific user
            v1=['course:edx/demo/2024']  # Specific course
        )
        ```

        Filter by multiple users and actions:
        ```python
        filter_obj = Filter(
            v0=['user:123', 'user:456'],  # Multiple users
            v2=['act:read', 'act:write']  # Multiple actions
        )
        ```
    """

    ptype: Optional[List[str]] = attr.field(factory=list)
    v0: Optional[List[str]] = attr.field(factory=list)
    v1: Optional[List[str]] = attr.field(factory=list)
    v2: Optional[List[str]] = attr.field(factory=list)
    v3: Optional[List[str]] = attr.field(factory=list)
    v4: Optional[List[str]] = attr.field(factory=list)
    v5: Optional[List[str]] = attr.field(factory=list)

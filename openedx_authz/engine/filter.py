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


class Filter:
    """
    Filter class for selective Casbin policy loading.

    This class defines filtering criteria used to load only specific policy rules
    from the database instead of loading all policies. Each attribute corresponds
    to a column in the Casbin policy storage schema and accepts a list of values
    to filter by.

    Attributes:
        ptype (list): Policy type filter (e.g., ['p', 'g'] for policy and grouping rules).
        v0 (list): First policy value filter (typically subject/user).
        v1 (list): Second policy value filter (typically object/resource).
        v2 (list): Third policy value filter (typically action/permission).
        v3 (list): Fourth policy value filter (additional context).
        v4 (list): Fifth policy value filter (additional context).
        v5 (list): Sixth policy value filter (additional context).

    Note:
        - Empty lists for any attribute means no filtering on that attribute
        - Non-empty lists create an "IN" filter for that attribute
        - All non-empty filters are combined with AND logic

    Examples:
        Filter by policy type only:
        ```python
        filter_obj = Filter()
        filter_obj.ptype = ['p']  # Only load policy rules, not grouping rules
        ```

        Filter by user and course:
        ```python
        filter_obj = Filter()
        filter_obj.v0 = ['user:student123']      # Specific user
        filter_obj.v1 = ['course:edx/demo/2024'] # Specific course
        ```

        Filter by multiple users and actions:
        ```python
        filter_obj = Filter()
        filter_obj.v0 = ['user:123', 'user:456']  # Multiple users
        filter_obj.v2 = ['read', 'write']         # Multiple actions
        ```
    """

    ptype = []
    v0 = []
    v1 = []
    v2 = []
    v3 = []
    v4 = []
    v5 = []

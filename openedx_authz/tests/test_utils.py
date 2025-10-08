"""Test utilities for creating namespaced keys using class constants."""

from openedx_authz.api.data import ActionData, ContentLibraryData, RoleData, ScopeData, UserData


def make_user_key(key: str) -> str:
    """Create a namespaced user key.

    Args:
        key: The user identifier (e.g., 'user-1', 'alice')

    Returns:
        str: Namespaced user key (e.g., 'user^user-1')
    """
    return f"{UserData.NAMESPACE}{UserData.SEPARATOR}{key}"


def make_role_key(key: str) -> str:
    """Create a namespaced role key.

    Args:
        key: The role identifier (e.g., 'platform_admin', 'library_editor')

    Returns:
        str: Namespaced role key (e.g., 'role^platform_admin')
    """
    return f"{RoleData.NAMESPACE}{RoleData.SEPARATOR}{key}"


def make_action_key(key: str) -> str:
    """Create a namespaced action key.

    Args:
        key: The action identifier (e.g., 'manage', 'edit', 'read')

    Returns:
        str: Namespaced action key (e.g., 'act^manage')
    """
    return f"{ActionData.NAMESPACE}{ActionData.SEPARATOR}{key}"


def make_library_key(key: str) -> str:
    """Create a namespaced library key.

    Args:
        key: The library identifier (e.g., 'lib:DemoX:CSPROB')

    Returns:
        str: Namespaced library key (e.g., 'lib^lib:DemoX:CSPROB')
    """
    return f"{ContentLibraryData.NAMESPACE}{ContentLibraryData.SEPARATOR}{key}"


def make_scope_key(namespace: str, key: str) -> str:
    """Create a namespaced scope key with custom namespace.

    Args:
        namespace: The scope namespace (e.g., 'org', 'course')
        key: The scope identifier (e.g., 'any-org', 'course-v1:...')

    Returns:
        str: Namespaced scope key (e.g., 'org^any-org')
    """
    return f"{namespace}{ScopeData.SEPARATOR}{key}"

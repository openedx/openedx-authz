"""Errors raised by the custom role API (ADR 0035).

They live in their own module because both the custom role operations and the role assignment
API raise them, and the custom role operations already depend on the assignment API.
"""

__all__ = [
    "CustomRoleError",
    "CustomRoleHasAssignmentsError",
    "CustomRoleNameTakenError",
    "CustomRoleNotFoundError",
    "InvalidCustomRoleError",
    "StaticRoleError",
]


class CustomRoleError(Exception):
    """Base class for the errors raised when changing or assigning custom roles."""


class CustomRoleNotFoundError(CustomRoleError):
    """No custom role with this ID exists, or it has been removed."""


class StaticRoleError(CustomRoleError):
    """The role is a static role, which cannot be edited or removed through custom role operations."""


class InvalidCustomRoleError(CustomRoleError):
    """The requested name or permissions cannot make a valid custom role."""


class CustomRoleNameTakenError(CustomRoleError):
    """Another role that has not been removed already uses the display name, ignoring case."""


class CustomRoleHasAssignmentsError(CustomRoleError):
    """The role still has assignments and the caller did not ask to delete them."""

    def __init__(self, role_id: str, assignment_count: int) -> None:
        """Keep the role and its number of assignments so callers can report them.

        Args:
            role_id (str): The ID of the custom role that was not removed.
            assignment_count (int): How many assignments the role still has.
        """
        super().__init__(
            f"Custom role {role_id!r} has {assignment_count} assignment(s); "
            "removing it requires explicitly deleting them."
        )
        self.role_id = role_id
        self.assignment_count = assignment_count

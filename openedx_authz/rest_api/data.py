"""Data classes and enums for the Open edX AuthZ REST API."""

from enum import Enum


class BaseEnum(str, Enum):
    """Base enum class."""

    @classmethod
    def values(cls):
        """List the values of the enum."""
        return [e.value for e in cls]


class SortField(BaseEnum):
    """Enum for the fields to sort by."""

    USERNAME = "username"
    FULL_NAME = "full_name"
    EMAIL = "email"


class SortOrder(BaseEnum):
    """Enum for the order to sort by."""

    ASC = "asc"
    DESC = "desc"


class SearchField(BaseEnum):
    """Enum for the fields allowed for text search filtering."""

    USERNAME = "username"
    FULL_NAME = "full_name"
    EMAIL = "email"


class RoleOperationStatus(BaseEnum):
    """Enum for the status of role assignment and removal operations."""

    ROLE_ADDED = "role_added"
    ROLE_REMOVED = "role_removed"


class RoleOperationError(BaseEnum):
    """Enum for errors that can occur during role assignment and removal operations."""

    USER_NOT_FOUND = "user_not_found"
    USER_ALREADY_HAS_ROLE = "user_already_has_role"
    USER_DOES_NOT_HAVE_ROLE = "user_does_not_have_role"
    ROLE_ASSIGNMENT_ERROR = "role_assignment_error"
    ROLE_REMOVAL_ERROR = "role_removal_error"

"""Enums for the Open edX AuthZ REST API."""

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

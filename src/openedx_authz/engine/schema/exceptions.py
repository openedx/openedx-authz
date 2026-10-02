"""Exceptions for the authz schema pipeline."""

from __future__ import annotations


class SchemaError(Exception):
    """Base class for schema pipeline errors."""


class SchemaLoadError(SchemaError):
    """A resource could not be parsed into a schema document."""


class SchemaValidationError(SchemaError):
    """Validation found error-level issues; deployment must stop.

    Carries the collected issues so the caller can report them all at once
    rather than failing on the first problem.
    """

    def __init__(self, issues):
        self.issues = issues
        super().__init__(f"Schema validation failed with {len(issues)} error(s).")


class SchemaCompileError(SchemaError):
    """Compilation could not resolve the definitions.

    For example, an unresolvable role_extension conflict at equal priority
    (ADR 0023).
    """


class SchemaApplyError(SchemaError):
    """Applying the rendered policy to the database is not safe to proceed.

    For example, a static role slated for removal still has user assignments
    and ``force`` was not set (ADR 0018 §6).
    """

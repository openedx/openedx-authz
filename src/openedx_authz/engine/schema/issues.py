"""Validation finding types shared by structural and semantic checks."""

from dataclasses import dataclass
from enum import StrEnum


class IssueLevel(StrEnum):
    """Severity of a :class:`ValidationIssue`.

    Members:
        ERROR: Blocks deployment.
        WARNING: Reported only, does not block deployment.
    """

    ERROR = "error"
    WARNING = "warning"


@dataclass(frozen=True)
class ValidationIssue:
    """A single validation finding.

    Attributes:
        level: :attr:`IssueLevel.ERROR` (blocks deployment) or
            :attr:`IssueLevel.WARNING` (reported only).
        message: Human-readable description.
        source_id: The contributing source, when the issue is file-specific.
    """

    level: IssueLevel
    message: str
    source_id: str | None = None

    @property
    def is_error(self) -> bool:
        """Return whether this finding blocks the pipeline."""
        return self.level == IssueLevel.ERROR

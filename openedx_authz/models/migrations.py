"""Models for tracking migration runs between legacy and AuthZ systems.

.. no_pii:
"""

from django.db import models
from django.utils import timezone


class MigrationType(models.TextChoices):
    """Direction of migration."""

    FORWARD = "forward", "Legacy to AuthZ"
    ROLLBACK = "rollback", "AuthZ to Legacy"


class Status(models.TextChoices):
    """Status of the migration task."""

    PENDING = "pending", "Pending"
    RUNNING = "running", "Running"
    COMPLETED = "completed", "Completed"
    SKIPPED = "skipped", "Skipped"


class ScopeType(models.TextChoices):
    """Type of scope being migrated."""

    COURSE = "course", "Course"
    ORG = "org", "Organization"


class AuthzCourseAuthoringMigrationRun(models.Model):
    """Track the status of course authoring migration tasks.

    This model is used to track async migrations between the legacy
    CourseAccessRole system and the new AuthZ system.
    """

    migration_type = models.CharField(
        max_length=20,
        choices=MigrationType,
        help_text="Direction of migration: forward (legacy → authz) or rollback (authz → legacy)",
    )

    scope_type = models.CharField(
        max_length=20,
        choices=ScopeType,
        help_text="Type of scope being migrated: course or organization",
    )

    scope_key = models.CharField(
        max_length=255,
        help_text="Identifier for the scope (e.g., course-v1:edX+DemoX+DemoCourse or org name)",
    )

    status = models.CharField(
        max_length=20,
        choices=Status,
        default=Status.PENDING,
        help_text="Current status of the migration run",
    )

    created_at = models.DateTimeField(
        auto_now_add=True,
        help_text="When the migration run was created",
    )

    updated_at = models.DateTimeField(
        auto_now=True,
        help_text="When the migration run was last updated",
    )

    completed_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="When the migration run was completed",
    )

    metadata = models.JSONField(
        default=dict,
        blank=True,
        help_text="Additional metadata about the migration run (e.g., counts, warnings)",
    )

    class Meta:
        verbose_name = "Course Authoring Migration Run"
        verbose_name_plural = "Course Authoring Migration Runs"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["scope_type", "scope_key"]),
            models.Index(fields=["status"]),
            models.Index(fields=["-created_at"]),
        ]

    @classmethod
    def create_pending(cls, migration_type, scope_type, scope_key, metadata=None) -> "AuthzCourseAuthoringMigrationRun":
        """Create a pending migration run."""
        return cls.objects.create(
            migration_type=migration_type,
            scope_type=scope_type,
            scope_key=scope_key,
            metadata=metadata or {},
        )

    def mark_running(self) -> None:
        """Mark the migration run as running."""
        self.status = Status.RUNNING
        self.save(update_fields=["status", "updated_at"])

    def mark_skipped(self, *, reason=None) -> None:
        """Mark the migration run as skipped."""
        self.status = Status.SKIPPED
        if reason:
            self.metadata = {**(self.metadata or {}), "skip_reason": reason}
            self.save(update_fields=["status", "updated_at", "metadata"])
            return
        self.save(update_fields=["status", "updated_at"])

    def mark_completed(self, *, metadata_updates=None) -> None:
        """Mark the migration run as completed."""
        self.status = Status.COMPLETED
        self.completed_at = timezone.now()
        if metadata_updates:
            self.metadata = {**(self.metadata or {}), **metadata_updates}
        self.save(update_fields=["status", "completed_at", "updated_at", "metadata"])

    def __str__(self) -> str:
        """Return a string representation of the migration run."""
        return f"[{self.id}] {self.migration_type} {self.scope_type}:{self.scope_key} {self.status}"

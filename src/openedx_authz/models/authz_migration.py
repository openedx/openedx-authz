"""Models for tracking migration runs between legacy and AuthZ systems."""

from django.db import IntegrityError, models, transaction
from django.utils import timezone


class MigrationType(models.TextChoices):
    """Direction of migration."""

    FORWARD = "forward", "Legacy to AuthZ"
    ROLLBACK = "rollback", "AuthZ to Legacy"


class Status(models.TextChoices):
    """Status of the migration task."""

    RUNNING = "running", "Running"
    COMPLETED = "completed", "Completed"
    PARTIAL_SUCCESS = "partial_success", "Partial Success"
    FAILED = "failed", "Failed"
    SKIPPED = "skipped", "Skipped"


class ScopeType(models.TextChoices):
    """Type of scope being migrated."""

    COURSE = "course", "Course"
    ORG = "org", "Organization"


class AuthzCourseAuthoringMigrationRun(models.Model):
    """Track the status of course authoring migration tasks.

    This model is used to track async migrations between the legacy
    CourseAccessRole system and the new AuthZ system.

    .. no_pii:
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
        default=Status.RUNNING,
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
        help_text="Additional metadata about the migration run (e.g., counts, warnings, errors)",
    )

    class Meta:
        verbose_name = "Course Authoring Migration Run"
        verbose_name_plural = "Course Authoring Migration Runs"
        ordering = ["-created_at"]

    def save(self, *args, **kwargs) -> "AuthzCourseAuthoringMigrationRun":
        """Enforce at most one RUNNING record per (scope_type, scope_key).

        MySQL does not support partial unique indexes, so this check is done at
        the application level. select_for_update() is used to reduce (but not
        fully eliminate) the race-condition window on concurrent inserts.
        """
        with transaction.atomic():
            if self.status == Status.RUNNING and self.pk is None:
                conflict = (
                    self.__class__.objects.select_for_update()
                    .filter(scope_type=self.scope_type, scope_key=self.scope_key, status=Status.RUNNING)
                    .exists()
                )
                if conflict:
                    raise IntegrityError(
                        f"Duplicate RUNNING migration run for scope {self.scope_type}:{self.scope_key}"
                    )
            super().save(*args, **kwargs)
        return self

    # pylint: disable=too-many-positional-arguments
    @classmethod
    def _create(
        cls, migration_type, scope_type, scope_key, status, metadata=None
    ) -> "AuthzCourseAuthoringMigrationRun":
        return cls.objects.create(
            migration_type=migration_type,
            scope_type=scope_type,
            scope_key=scope_key,
            status=status,
            metadata=metadata or {},
        )

    @classmethod
    def create_running(
        cls,
        migration_type,
        scope_type,
        scope_key,
        metadata=None,
    ) -> "AuthzCourseAuthoringMigrationRun":
        """Create a migration run in running state."""
        return cls._create(migration_type, scope_type, scope_key, Status.RUNNING, metadata)

    @classmethod
    def create_skipped(
        cls,
        migration_type,
        scope_type,
        scope_key,
        metadata=None,
    ) -> "AuthzCourseAuthoringMigrationRun":
        """Create a migration run in skipped state."""
        extra = {**(metadata or {}), "skip_reason": "A concurrent migration run is already active for this scope."}
        return cls._create(migration_type, scope_type, scope_key, Status.SKIPPED, extra)

    def _finalize(self, status: str, metadata_updates: dict | None = None) -> "AuthzCourseAuthoringMigrationRun":
        """Finalize the migration run."""
        self.status = status
        self.completed_at = timezone.now()
        if metadata_updates:
            self.metadata = {**(self.metadata or {}), **metadata_updates}
        return self.save(update_fields=["status", "completed_at", "updated_at", "metadata"])

    def mark_partial_success(self, *, metadata_updates=None) -> "AuthzCourseAuthoringMigrationRun":
        """Mark the migration run as partially successful."""
        return self._finalize(Status.PARTIAL_SUCCESS, metadata_updates)

    def mark_completed(self, *, metadata_updates=None) -> "AuthzCourseAuthoringMigrationRun":
        """Mark the migration run as completed."""
        return self._finalize(Status.COMPLETED, metadata_updates)

    def mark_failed(self, *, exception=None) -> "AuthzCourseAuthoringMigrationRun":
        """Mark the migration run as failed."""
        return self._finalize(Status.FAILED, {"error": str(exception)} if exception is not None else None)

    def __str__(self) -> str:
        """Return a string representation of the migration run."""
        return f"[{self.id}] {self.migration_type} {self.scope_type}:{self.scope_key} {self.status}"

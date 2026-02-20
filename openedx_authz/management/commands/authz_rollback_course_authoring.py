"""
Django management command to rollback course authoring roles from the new Authz (Casbin-based)
authorization system back to the legacy CourseAccessRole model.
"""

from django.core.management.base import BaseCommand
from django.db import transaction

from openedx_authz.engine.utils import migrate_authz_to_legacy_course_roles
from openedx_authz.models.subjects import UserSubject

try:
    from common.djangoapps.student.models import CourseAccessRole
except ImportError:
    CourseAccessRole = None  # type: ignore


class Command(BaseCommand):
    """
    Django command to rollback course authoring roles
    from the new Authz system back to legacy CourseAccessRole.
    """

    help = "Rollback Authz course authoring roles to legacy CourseAccessRole."

    def add_arguments(self, parser):
        parser.add_argument(
            "--delete",
            action="store_true",
            help="Delete Authz role assignments after successful rollback.",
        )

    def handle(self, *args, **options):
        delete_after_migration = options["delete"]

        self.stdout.write(self.style.WARNING("Starting Authz → Legacy rollback migration..."))

        try:
            if delete_after_migration:
                confirm = input(
                    "Are you sure you want to remove the new Authz role "
                    "assignments after rollback? Type 'yes' to continue: "
                )

                if confirm != "yes":
                    self.stdout.write(self.style.WARNING("Deletion aborted."))
                    return
            with transaction.atomic():
                errors = migrate_authz_to_legacy_course_roles(
                    CourseAccessRole=CourseAccessRole,
                    UserSubject=UserSubject,
                    delete_after_migration=delete_after_migration,  # control deletion here
                )

                if errors:
                    self.stdout.write(self.style.ERROR(f"Rollback completed with {len(errors)} errors."))
                else:
                    self.stdout.write(self.style.SUCCESS("Rollback completed successfully with no errors."))

                if delete_after_migration:
                    self.stdout.write(self.style.SUCCESS("Authz role assignments removed successfully."))

        except Exception as exc:
            self.stdout.write(self.style.ERROR(f"Rollback failed due to unexpected error: {exc}"))
            raise

        self.stdout.write(self.style.SUCCESS("Done."))

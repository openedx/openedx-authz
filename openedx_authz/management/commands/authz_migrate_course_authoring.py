"""
Django management command to migrate legacy course authoring roles to the new Authz (Casbin-based) authorization system.
"""

from django.core.management.base import BaseCommand
from django.db import transaction

from openedx_authz.engine.utils import migrate_legacy_course_roles_to_authz

try:
    from common.djangoapps.student.models import CourseAccessRole
except ImportError:
    CourseAccessRole = None  # type: ignore


class Command(BaseCommand):
    """
    Django command to migrate legacy CourseAccessRole data
    to the new Authz (Casbin-based) authorization system.
    """

    help = "Migrate legacy course authoring roles to the new Authz system."

    def add_arguments(self, parser):
        parser.add_argument(
            "--delete",
            action="store_true",
            help="Delete legacy CourseAccessRole records after successful migration.",
        )

    def handle(self, *args, **options):
        delete_after_migration = options["delete"]

        self.stdout.write(self.style.WARNING("Starting legacy → Authz migration..."))

        try:
            if delete_after_migration:
                confirm = input(
                    "Are you sure you want to delete successfully migrated legacy roles? Type 'yes' to continue: "
                )

                if confirm != "yes":
                    self.stdout.write(self.style.WARNING("Deletion aborted."))
                    return
            with transaction.atomic():
                errors = migrate_legacy_course_roles_to_authz(
                    CourseAccessRole=CourseAccessRole,
                    delete_after_migration=delete_after_migration,
                )

                if errors:
                    self.stdout.write(self.style.ERROR(f"Migration completed with {len(errors)} errors."))
                else:
                    self.stdout.write(self.style.SUCCESS("Migration completed successfully with no errors."))

                if delete_after_migration:
                    self.stdout.write(self.style.SUCCESS("Legacy roles deleted successfully."))

        except Exception as exc:
            self.stdout.write(self.style.ERROR(f"Migration failed due to unexpected error: {exc}"))
            raise

        self.stdout.write(self.style.SUCCESS("Done."))

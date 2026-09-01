"""Django management command to seed the Sandbox environment with deterministic test data.

Reads a JSON fixture describing organizations, users, and authz role assignments and
inserts it idempotently (get_or_create), so the command is safe to run repeatedly
against a Sandbox database without creating duplicates.

Example usage:
    python manage.py lms seed_sandbox_data
    python manage.py lms seed_sandbox_data --data-file /path/to/custom.json
    python manage.py lms seed_sandbox_data --reset
"""

import json
import logging
import os

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError
from organizations.api import add_organization, get_organizations

from openedx_authz import ROOT_DIRECTORY
from openedx_authz.api.users import assign_role_to_user_in_scope
from openedx_authz.engine.enforcer import AuthzEnforcer

log = logging.getLogger(__name__)

DEFAULT_DATA_FILE = os.path.join(ROOT_DIRECTORY, "management", "commands", "data", "sandbox_seed_data.json")
DEFAULT_PASSWORD = "edx"


class Command(BaseCommand):
    """Seed the Sandbox environment with a base set of orgs, users, and authz role assignments."""

    help = "Seed the Sandbox environment with orgs, users, and authz role assignments from a JSON fixture."

    def add_arguments(self, parser) -> None:
        parser.add_argument(
            "--data-file",
            type=str,
            default=None,
            help="Path to the JSON seed data file (default: bundled sandbox_seed_data.json).",
        )
        parser.add_argument(
            "--reset",
            action="store_true",
            help="Delete previously seeded users (identified by username) before seeding.",
        )

    def handle(self, *args, **options):
        data_file = options["data_file"] or DEFAULT_DATA_FILE
        with open(data_file, encoding="utf-8") as fh:
            seed_data = json.load(fh)

        user_model = get_user_model()
        usernames = [user["username"] for user in seed_data.get("users", [])]

        if options["reset"]:
            deleted, _ = user_model.objects.filter(username__in=usernames).delete()
            self.stdout.write(self.style.WARNING(f"Removed {deleted} previously seeded record(s)."))

        counts = {"created": 0, "skipped": 0, "failed": 0}
        self._seed_organizations(seed_data.get("organizations", []), counts)
        self._seed_users(seed_data.get("users", []), user_model, counts)

        AuthzEnforcer.get_enforcer().load_policy()

        summary = "Seeding complete: {created} created, {skipped} skipped, {failed} failed.".format(**counts)
        if counts["failed"]:
            self.stdout.write(self.style.ERROR(summary))
            raise CommandError(f"{counts['failed']} seed item(s) failed, see logs above for details.")
        self.stdout.write(self.style.SUCCESS(summary))

    def _seed_organizations(self, organizations, counts):
        """Create any organization from the fixture that doesn't already exist, tallying counts."""
        existing = {org["short_name"] for org in get_organizations()}
        for org in organizations:
            if org["short_name"] in existing:
                counts["skipped"] += 1
                continue
            try:
                add_organization(org)
                counts["created"] += 1
            # One bad organization shouldn't stop the rest of the fixture from seeding.
            except Exception:  # pylint: disable=broad-exception-caught
                log.exception("Failed to create organization %s", org.get("short_name"))
                counts["failed"] += 1

    def _seed_users(self, users, user_model, counts):
        """Create/update each user from the fixture and assign their roles, tallying counts."""
        for user_data in users:
            username = user_data["username"]
            user, was_created = user_model.objects.get_or_create(
                username=username,
                defaults={"email": user_data.get("email", f"{username}@example.com")},
            )
            if was_created:
                user.set_password(user_data.get("password", DEFAULT_PASSWORD))
                user.is_staff = user_data.get("is_staff", False)
                user.is_superuser = user_data.get("is_superuser", False)
                user.save()
                counts["created"] += 1
            else:
                counts["skipped"] += 1

            for assignment in user_data.get("roles", []):
                try:
                    assign_role_to_user_in_scope(username, assignment["role"], assignment["scope"])
                # One bad role assignment shouldn't stop the rest of the fixture from seeding.
                except Exception:  # pylint: disable=broad-exception-caught
                    log.exception(
                        "Failed to assign role %s to %s in scope %s",
                        assignment["role"],
                        username,
                        assignment["scope"],
                    )
                    counts["failed"] += 1

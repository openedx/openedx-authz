"""Celery tasks for course authoring migration.
These tasks handle asynchronous migration between legacy CourseAccessRole
and the new AuthZ system.
"""

import logging

from django.db import transaction

# from celery import shared_task
from openedx_authz.engine.utils import migrate_authz_to_legacy_course_roles, migrate_legacy_course_roles_to_authz
from openedx_authz.models.migrations import MigrationType, ScopeType
from openedx_authz.models.subjects import UserSubject

try:
    from common.djangoapps.student.models import CourseAccessRole
except ImportError:
    CourseAccessRole = None

logger = logging.getLogger(__name__)


# @shared_task(bind=True)
def migrate_course_authoring_async(
    # self,
    migration_type: MigrationType | None,
    scope_type: ScopeType,
    scope_key: str,
    course_id_list: list[str] | None = None,
    org_id: str | None = None,
    delete_after: bool = True,
):
    """Asynchronously migrate course authoring roles between legacy and AuthZ systems.
    Args:
        migration_type: 'forward' (legacy→authz) or 'rollback' (authz→legacy)
        scope_type: 'course' or 'org'
        scope_key: Identifier for the scope
        course_id_list: Optional list of course IDs to migrate (for course scope)
        org_id: Optional organization ID to migrate (for org scope)
        delete_after: Whether to delete source roles after successful migration
    Returns:
        dict: Migration result with status and metadata
    """
    with transaction.atomic():
        if migration_type == MigrationType.FORWARD:
            errors, successes = migrate_legacy_course_roles_to_authz(
                course_access_role_model=CourseAccessRole,
                course_id_list=course_id_list,
                org_id=org_id,
                delete_after_migration=delete_after,
            )
        elif migration_type == MigrationType.ROLLBACK:
            errors, successes = migrate_authz_to_legacy_course_roles(
                course_access_role_model=CourseAccessRole,
                user_subject_model=UserSubject,
                course_id_list=course_id_list,
                org_id=org_id,
                delete_after_migration=delete_after,
            )
        else:
            raise ValueError(f"Invalid migration_type: {migration_type}")

    logger.info(
        f"Completed {migration_type} migration for {scope_type}:{scope_key}. "
        f"Successes: {len(successes)}, Errors: {len(errors)}"
    )

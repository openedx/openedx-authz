"""
Signal handlers for the authorization framework.

These handlers ensure proper cleanup and consistency when models are deleted.
"""

from __future__ import annotations

import logging

from casbin_adapter.models import CasbinRule
from django.conf import settings
from django.db.models.signals import post_delete, post_save
from django.dispatch import receiver

from openedx_authz.api.users import unassign_all_roles_from_user
from openedx_authz.engine.utils import run_course_authoring_migration
from openedx_authz.models.authz_migration import MigrationType, ScopeType
from openedx_authz.models.core import ExtendedCasbinRule
from openedx_authz.models.subjects import UserSubject

try:
    from common.djangoapps.student.models import CourseAccessRole
    from openedx.core.djangoapps.user_api.accounts.signals import USER_RETIRE_LMS_CRITICAL
    from openedx.core.djangoapps.waffle_utils.models import WaffleFlagCourseOverrideModel, WaffleFlagOrgOverrideModel
    from openedx.core.toggles import AUTHZ_COURSE_AUTHORING_FLAG
except ImportError:
    USER_RETIRE_LMS_CRITICAL = None
    WaffleFlagCourseOverrideModel = None
    WaffleFlagOrgOverrideModel = None
    AUTHZ_COURSE_AUTHORING_FLAG = None
    CourseAccessRole = None


logger = logging.getLogger(__name__)


@receiver(post_delete, sender=ExtendedCasbinRule)
def delete_casbin_rule_on_extended_rule_deletion(sender, instance, **kwargs):  # pylint: disable=unused-argument
    """
    Delete the companion CasbinRule after its ExtendedCasbinRule disappears.

    The handler keeps authorization data symmetric with three common flows:

    - Direct ExtendedCasbinRule deletes (API/UI) trigger removal of the linked CasbinRule.
    - Cascades from `Scope` or `Subject` deletions clear their ExtendedCasbinRule rows and,
      via this handler, the matching CasbinRule entries.
    - Cascades initiated from the CasbinRule side (enforcer cleanups) leave the query as a
      no-op because the row is already gone.

    Running on ``post_delete`` ensures database cascades complete before the cleanup runs, so
    enforcer-driven deletions no longer raise false errors.

    Args:
        sender: The model class (ExtendedCasbinRule).
        instance: The ExtendedCasbinRule instance being deleted.
        **kwargs: Additional keyword arguments from the signal.
    """
    try:
        # Rely on delete() being idempotent; returns 0 rows if the CasbinRule was
        # already removed (for example, because it triggered this signal).
        CasbinRule.objects.filter(id=instance.casbin_rule_id).delete()
    except Exception as exc:  # pylint: disable=broad-exception-caught
        # Log but don't raise - we don't want to break the deletion of
        # ExtendedCasbinRule if something goes wrong while deleting the CasbinRule.
        logger.exception(
            "Error deleting CasbinRule %s during ExtendedCasbinRule cleanup",
            instance.casbin_rule_id,
            exc_info=exc,
        )


def unassign_roles_on_user_retirement(sender, user, **kwargs):  # pylint: disable=unused-argument
    """
    Unassign roles from a user when they are retired.

    This handler is triggered when a user is retired in the LMS. It ensures that
    any roles assigned to the user are removed, maintaining the integrity of the
    authorization system.

    Args:
        sender: The model class (User).
        user: The user instance being retired.
        **kwargs: Additional keyword arguments from the signal.
    """
    try:
        unassign_all_roles_from_user(user.username)
    except Exception as exc:  # pylint: disable=broad-exception-caught
        logger.exception(
            "Error unassigning roles from user %s during retirement",
            user.id,
            exc_info=exc,
        )


# Only register the handler if the signal is available (i.e., running in Open edX)
if USER_RETIRE_LMS_CRITICAL is not None:
    USER_RETIRE_LMS_CRITICAL.connect(unassign_roles_on_user_retirement)


def handle_course_waffle_flag_change(sender, instance, **kwargs) -> None:
    """
    Handle changes to course-level waffle flags.

    When the authz.enable_course_authoring flag is changed for a course,
    trigger the appropriate migration run. Only trigger if automatic migration
    is enabled in the settings.

    Args:
        sender: The model class (WaffleFlagCourseOverrideModel)
        instance: The flag override instance being saved
        **kwargs: Additional keyword arguments from the signal
    """
    trigger_course_authoring_migration(sender=sender, instance=instance, scope_key=str(instance.course_id))


def handle_org_waffle_flag_change(sender, instance, **kwargs) -> None:
    """
    Handle changes to organization-level waffle flags.

    When the authz.enable_course_authoring flag is changed for an organization,
    trigger the appropriate migration run. Only trigger if automatic migration
    is enabled in the settings.

    Args:
        sender: The model class (WaffleFlagOrgOverrideModel)
        instance: The flag override instance being saved
        **kwargs: Additional keyword arguments from the signal
    """
    trigger_course_authoring_migration(sender=sender, instance=instance, scope_key=str(instance.org))


# Only register the handlers if the models are available (i.e., running in Open edX)
if WaffleFlagCourseOverrideModel is not None:
    post_save.connect(handle_course_waffle_flag_change, sender=WaffleFlagCourseOverrideModel)

if WaffleFlagOrgOverrideModel is not None:
    post_save.connect(handle_org_waffle_flag_change, sender=WaffleFlagOrgOverrideModel)


def trigger_course_authoring_migration(
    sender: type[WaffleFlagCourseOverrideModel | WaffleFlagOrgOverrideModel],
    instance: WaffleFlagCourseOverrideModel | WaffleFlagOrgOverrideModel,
    scope_key: str,
) -> None:
    """
    Trigger a migration run in response to a waffle flag change.

    Determines the migration direction from the flag state, guards against
    no-op saves, and delegates execution to ``run_course_authoring_migration``
    which handles tracking and concurrent-run protection.

    Args:
        sender: The model class (WaffleFlagCourseOverrideModel or WaffleFlagOrgOverrideModel).
        instance: The waffle flag instance that triggered the migration.
        scope_key (str): Course ID or organization name.
    """
    if not settings.ENABLE_AUTOMATIC_AUTHZ_COURSE_AUTHORING_MIGRATION:
        logger.info("ENABLE_AUTOMATIC_AUTHZ_COURSE_AUTHORING_MIGRATION is set to False, skipping migration")
        return

    if instance.waffle_flag != AUTHZ_COURSE_AUTHORING_FLAG.name:
        return

    course_id_list, org_id, scope_type = None, None, None
    filter_kwargs = {"waffle_flag": AUTHZ_COURSE_AUTHORING_FLAG.name}
    if isinstance(instance, WaffleFlagCourseOverrideModel):
        filter_kwargs["course_id"] = instance.course_id
        course_id_list = [scope_key]
        scope_type = ScopeType.COURSE
    elif isinstance(instance, WaffleFlagOrgOverrideModel):
        filter_kwargs["org"] = instance.org
        org_id = scope_key
        scope_type = ScopeType.ORG
    else:
        logger.error("Unsupported waffle flag instance: %s", instance)
        return

    prev_record = sender.objects.filter(**filter_kwargs).exclude(id=instance.id).order_by("-change_date").first()

    if prev_record and prev_record.enabled == instance.enabled:
        logger.info("No change in waffle flag, skipping course migration")
        return

    migration_type = MigrationType.FORWARD if instance.enabled else MigrationType.ROLLBACK

    logger.info("Triggering %s migration for %s:%s due to waffle flag change", migration_type, scope_type, scope_key)

    run_course_authoring_migration(
        migration_type=migration_type,
        scope_type=scope_type,
        scope_key=scope_key,
        course_access_role_model=CourseAccessRole,
        user_subject_model=UserSubject,
        course_id_list=course_id_list,
        org_id=org_id,
    )

"""
Signal handlers for the authorization framework.

These handlers ensure proper cleanup and consistency when models are deleted.
"""

import logging

from casbin_adapter.models import CasbinRule
from django.conf import settings
from django.db.models.signals import post_delete, pre_save
from django.dispatch import receiver

from openedx_authz.api.users import unassign_all_roles_from_user
from openedx_authz.models.core import ExtendedCasbinRule
from openedx_authz.models.migrations import MigrationType, ScopeType
from openedx_authz.tasks import migrate_course_authoring_async

try:
    from openedx.core.djangoapps.user_api.accounts.signals import USER_RETIRE_LMS_CRITICAL
except ImportError:
    USER_RETIRE_LMS_CRITICAL = None

try:
    from openedx.core.djangoapps.waffle_utils.models import WaffleFlagCourseOverrideModel, WaffleFlagOrgOverrideModel
except ImportError:
    WaffleFlagCourseOverrideModel = None
    WaffleFlagOrgOverrideModel = None


logger = logging.getLogger(__name__)

# Flag name to monitor for automatic migration
AUTHZ_COURSE_AUTHORING_FLAG = "authz.enable_course_authoring"


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


def trigger_course_authoring_migration(
    instance: WaffleFlagCourseOverrideModel | WaffleFlagOrgOverrideModel,
    scope_type: ScopeType,
    scope_key: str,
) -> None:
    """Trigger an asynchronous migration run.

    Args:
        instance: The waffle flag instance that triggered the migration
        scope_type (ScopeType): Type of scope being migrated: course or organization
        scope_key (str): Course ID or organization name
    """
    if instance.waffle_flag != AUTHZ_COURSE_AUTHORING_FLAG:
        return

    last_flag_obj = None
    if isinstance(instance, WaffleFlagCourseOverrideModel):
        last_flag_obj = (
            WaffleFlagCourseOverrideModel.objects.filter(course_id=instance.course_id).order_by("-id").first()
        )
    elif isinstance(instance, WaffleFlagOrgOverrideModel):
        last_flag_obj = WaffleFlagOrgOverrideModel.objects.filter(org=instance.org).order_by("-id").first()

    if last_flag_obj and last_flag_obj.enabled == instance.enabled:
        logger.info("No change in waffle flag, skipping course migration")
        return

    if not instance.enabled:
        migration_type = MigrationType.ROLLBACK
    else:
        migration_type = MigrationType.FORWARD

    course_id_list = None
    org_id = None

    if scope_type == ScopeType.COURSE:
        course_id_list = [scope_key]
    elif scope_type == ScopeType.ORG:
        org_id = scope_key

    logger.info(f"Triggering {migration_type} migration for {scope_type}:{scope_key} due to waffle flag change")

    migrate_course_authoring_async(
        migration_type=migration_type,
        scope_type=scope_type,
        scope_key=scope_key,
        course_id_list=course_id_list,
        org_id=org_id,
        delete_after=True,
    )


@receiver(pre_save, sender=WaffleFlagCourseOverrideModel)
def handle_course_waffle_flag_change(sender, instance, **kwargs) -> None:  # pylint: disable=unused-argument
    """Handle changes to course-level waffle flags.

    When the authz.enable_course_authoring flag is changed for a course,
    trigger the appropriate migration run. Only trigger if automatic migration
    is enabled in the settings.

    Args:
        sender: The model class (WaffleFlagCourseOverrideModel)
        instance: The flag override instance being saved
        **kwargs: Additional keyword arguments from the signal
    """
    if not settings.ENABLE_AUTOMATIC_AUTHZ_COURSE_AUTHORING_MIGRATION:
        logger.info("Automatic migration is disabled, skipping course migration")
        return

    trigger_course_authoring_migration(
        instance=instance,
        scope_type=ScopeType.COURSE,
        scope_key=str(instance.course_id),
    )


@receiver(pre_save, sender=WaffleFlagOrgOverrideModel)
def handle_org_waffle_flag_change(sender, instance, **kwargs) -> None:  # pylint: disable=unused-argument
    """Handle changes to organization-level waffle flags.

    When the authz.enable_course_authoring flag is changed for an organization,
    trigger the appropriate migration run. Only trigger if automatic migration
    is enabled in the settings.

    Args:
        sender: The model class (WaffleFlagOrgOverrideModel)
        instance: The flag override instance being saved
        **kwargs: Additional keyword arguments from the signal
    """
    if not settings.ENABLE_AUTOMATIC_AUTHZ_COURSE_AUTHORING_MIGRATION:
        logger.info("Automatic migration is disabled, skipping organization migration")
        return

    trigger_course_authoring_migration(
        instance=instance,
        scope_type=ScopeType.ORG,
        scope_key=str(instance.org),
    )

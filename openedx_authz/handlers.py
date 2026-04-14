"""
Signal handlers for the authorization framework.

These handlers ensure proper cleanup and consistency when models are deleted.
"""

from __future__ import annotations

import logging
from typing import Union

from casbin_adapter.models import CasbinRule
from django.conf import settings
from django.db.models.signals import post_delete, post_save
from django.dispatch import receiver
from waffle.models import Flag

from openedx_events.authz.signals import ROLE_ASSIGNMENT_CREATED, ROLE_ASSIGNMENT_DELETED

from openedx_authz.api.users import unassign_all_roles_from_user
from openedx_authz.engine.utils import run_course_authoring_migration
from openedx_authz.models.authz_migration import MigrationType, ScopeType
from openedx_authz.models.core import ExtendedCasbinRule
from openedx_authz.models.subjects import UserSubject
from openedx_authz.api.users import unassign_all_roles_from_user
from openedx_authz.models.core import ExtendedCasbinRule, RoleAssignmentAudit

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


# Match ``WaffleFlagCourseOverrideModel.OVERRIDE_CHOICES`` / ``override_value`` in edx-platform:
# the flag is effectively forced on only when the row is enabled and ``override_choice`` is "on".
WAFFLE_OVERRIDE_FORCE_ON = "on"
WAFFLE_OVERRIDE_FORCE_OFF = "off"


# Type Alias for better readability
WaffleOverrideRecord = Union[WaffleFlagCourseOverrideModel, WaffleFlagOrgOverrideModel]


def get_effective_state(record: WaffleOverrideRecord | None, global_flag_enabled: bool) -> bool:
    """
    Return whether the feature is effectively active for the override and global flag.

    An enabled override forces on or off, otherwise the result follows the global flag.

    Args:
        record (WaffleOverrideRecord | None): The waffle flag record to evaluate.
        global_flag_enabled (bool): The state of the global flag.

    Returns:
        bool: True if the feature is active, False otherwise.
    """
    # If there is no override, or the override is disabled, the state falls back to the global flag.
    if not record or not record.enabled:
        return global_flag_enabled

    # If there is an active override, it dictates the state, ignoring the global flag.
    if record.override_choice == WAFFLE_OVERRIDE_FORCE_ON:
        return True
    if record.override_choice == WAFFLE_OVERRIDE_FORCE_OFF:
        return False

    # Safety fallback (in case override_choice is corrupted or empty)
    return global_flag_enabled


def get_migration_type(
    current_record: WaffleOverrideRecord,
    previous_record: WaffleOverrideRecord | None,
    global_flag_enabled: bool,
) -> MigrationType | None:
    """
    Determine the migration type by comparing the effective state before and after the transaction.

    This accounts for the global flag state, meaning a transition could be triggered by
    removing a FORCE_OFF override when the global flag is ON.

    Args:
        current_record (WaffleOverrideRecord): The state of the record in the current transaction.
        previous_record (WaffleOverrideRecord | None): The state of the record prior to the current transaction.
        global_flag_enabled (bool): The state of the global flag.

    Returns:
        MigrationType.FORWARD: If the flag is newly forced on.
        MigrationType.ROLLBACK: If the forced-on state is removed.
        None: If there is no effective change in the flag's behavior.
    """
    was_effectively_active = get_effective_state(previous_record, global_flag_enabled)
    is_effectively_active = get_effective_state(current_record, global_flag_enabled)

    # If the effective behavior hasn't changed, we don't need to do anything
    if is_effectively_active == was_effectively_active:
        return None

    # If it is now effectively active (and wasn't before), migrate forward. Otherwise, rollback.
    return MigrationType.FORWARD if is_effectively_active else MigrationType.ROLLBACK


def get_excluded_course_ids_for_org_migration(org_id: str, override_choice: str) -> frozenset[str]:
    """
    Collect course-level authoring flag overrides for an org that oppose the new org-level state.

    When the org flag changes, we need to exclude course ids that have a course-level
    authoring flag override that opposes the new org-level state.

    Args:
        org_id (str): Organization short name.
        override_choice (str): The override choice of the org waffle flag.

    Returns:
        frozenset[str]: course ids excluded from org migration
    """
    # We only need to check the current set (active flags). Opposing overrides are rows that
    # force the opposite of the org transition (Force On vs Force Off), not merely inactive rows.
    reverse_choice = (
        WAFFLE_OVERRIDE_FORCE_ON if override_choice == WAFFLE_OVERRIDE_FORCE_OFF else WAFFLE_OVERRIDE_FORCE_OFF
    )
    filter_kwargs = {
        "waffle_flag": AUTHZ_COURSE_AUTHORING_FLAG.name,
        "course_id__startswith": f"course-v1:{org_id}+",
        "enabled": True,
        "override_choice": reverse_choice,
    }
    qs = WaffleFlagCourseOverrideModel.objects.current_set().filter(**filter_kwargs)
    return frozenset(map(str, qs.values_list("course_id", flat=True)))


def trigger_course_authoring_migration(
    sender: type[WaffleOverrideRecord],
    instance: WaffleOverrideRecord,
    scope_key: str,
) -> None:
    """
    Trigger a migration run in response to a waffle flag change.

    Determines the migration direction from the flag state, guards against
    no-op saves, and delegates execution to ``run_course_authoring_migration``
    which handles tracking and concurrent-run protection.

    Args:
        sender: The model class (WaffleOverrideRecord).
        instance: The waffle flag instance that triggered the migration.
        scope_key (str): Course ID or organization name.
    """
    if instance.waffle_flag != AUTHZ_COURSE_AUTHORING_FLAG.name:
        return

    if not settings.ENABLE_AUTOMATIC_AUTHZ_COURSE_AUTHORING_MIGRATION:
        logger.info("ENABLE_AUTOMATIC_AUTHZ_COURSE_AUTHORING_MIGRATION is set to False, skipping migration")
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

    global_flag = Flag.objects.filter(name=AUTHZ_COURSE_AUTHORING_FLAG.name).first()
    global_flag_enabled = bool(global_flag and global_flag.everyone)

    migration_type = get_migration_type(instance, prev_record, global_flag_enabled)
    if migration_type is None:
        logger.info("No effective change in waffle flag behavior, skipping migration")
        return

    excluded_course_ids = frozenset()
    if isinstance(instance, WaffleFlagOrgOverrideModel):
        excluded_course_ids = get_excluded_course_ids_for_org_migration(
            org_id=scope_key, override_choice=instance.override_choice
        )

    logger.info("Triggering %s migration for %s:%s due to waffle flag change", migration_type, scope_type, scope_key)

    run_course_authoring_migration(
        migration_type=migration_type,
        scope_type=scope_type,
        scope_key=scope_key,
        course_access_role_model=CourseAccessRole,
        user_subject_model=UserSubject,
        course_id_list=course_id_list,
        org_id=org_id,
        excluded_course_ids=excluded_course_ids,
        delete_after_migration=True,
    )


@receiver(ROLE_ASSIGNMENT_CREATED)
@receiver(ROLE_ASSIGNMENT_DELETED)
def create_audit_record_on_role_assignment_change(sender, role_assignment, **kwargs):  # pylint: disable=unused-argument
    """
    Create an audit record when a role assignment is created or deleted.

    This handler listens for both creation and deletion of role assignments and logs the changes
    for auditing purposes.

    Args:
        sender: The signal class (ROLE_ASSIGNMENT_CREATED or ROLE_ASSIGNMENT_DELETED).
        role_assignment: RoleAssignmentEventData carrying the operation, subject, role, scope, and actor.
        **kwargs: Additional keyword arguments from the signal.
    """
    try:
        RoleAssignmentAudit.objects.create(
            operation=role_assignment.operation,
            subject=role_assignment.subject,
            role=role_assignment.role,
            scope=role_assignment.scope,
            actor=role_assignment.actor,
            timestamp=kwargs["metadata"].time,
        )
    except Exception as exc:  # pylint: disable=broad-exception-caught
        logger.exception(
            "Error creating audit record for role assignment change: %s",
            exc,
        )

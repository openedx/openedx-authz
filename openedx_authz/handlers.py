"""
Signal handlers for the authorization framework.

These handlers ensure proper cleanup and consistency when models are deleted.
"""

import logging

from casbin_adapter.models import CasbinRule
from django.db.models.signals import post_delete
from django.dispatch import receiver

from openedx_authz.models.core import ExtendedCasbinRule

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

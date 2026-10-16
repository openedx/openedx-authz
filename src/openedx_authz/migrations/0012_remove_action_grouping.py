"""Remove obsolete Casbin action-grouping rows."""

import logging

from django.db import migrations
from django.db.utils import DatabaseError

logger = logging.getLogger(__name__)


def remove_action_grouping(apps, schema_editor):
    """Delete g2 rows when their historical model and table are available."""
    try:
        casbin_rule = apps.get_model("casbin_adapter", "CasbinRule")
    except LookupError:
        logger.warning("Skipping action-grouping cleanup because CasbinRule is unavailable.")
        return

    database = schema_editor.connection.alias
    try:
        casbin_rule.objects.using(database).filter(ptype="g2").delete()
    except DatabaseError:
        # This cleanup must not block a deployment. The current Casbin model does not
        # define g2, so any rows left behind are ignored and can be removed later.
        logger.warning(
            "Could not remove action-grouping rows. They are ignored by the current Casbin model.",
            exc_info=True,
        )


class Migration(migrations.Migration):
    """Remove stored action inheritance that is no longer supported."""

    dependencies = [
        ("openedx_authz", "0011_authz_schema_definitions"),
    ]

    operations = [
        migrations.RunPython(remove_action_grouping, migrations.RunPython.noop, atomic=False),
    ]

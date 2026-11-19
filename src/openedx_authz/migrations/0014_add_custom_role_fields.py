"""Add the fields that tell custom roles from static roles (ADR 0035).

Existing rows are all static roles, so the column defaults leave them correct and no data needs to
move.
"""

from django.db import migrations, models


class Migration(migrations.Migration):
    """Add ``definition_kind`` and ``removed_at`` to role definitions."""

    dependencies = [
        ("openedx_authz", "0013_add_hidden_to_categories_and_permissions"),
    ]

    operations = [
        migrations.AddField(
            model_name="authzroledefinition",
            name="definition_kind",
            field=models.CharField(
                choices=[("static", "Static"), ("user_defined", "User defined")],
                default="static",
                max_length=16,
            ),
        ),
        migrations.AddField(
            model_name="authzroledefinition",
            name="removed_at",
            field=models.DateTimeField(
                blank=True,
                help_text="When the row was removed. Empty while it is in use.",
                null=True,
            ),
        ),
    ]

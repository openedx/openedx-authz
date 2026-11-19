"""Add the fields that tell custom roles from static roles (ADR 0035).

Existing rows are all static roles, so the column defaults leave them correct and no data needs to
move. The check constraints keep the three facts about custom roles true in the database: they are
never hidden, only they carry a removal time, and their IDs start with the reserved prefix.
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
                help_text="When the custom role was removed. Always empty for static roles.",
                null=True,
            ),
        ),
        migrations.AddConstraint(
            model_name="authzroledefinition",
            constraint=models.CheckConstraint(
                condition=models.Q(("definition_kind", "user_defined"), ("hidden", True), _negated=True),
                name="authz_role_custom_not_hidden",
            ),
        ),
        migrations.AddConstraint(
            model_name="authzroledefinition",
            constraint=models.CheckConstraint(
                condition=models.Q(("removed_at__isnull", True), ("definition_kind", "user_defined"), _connector="OR"),
                name="authz_role_removed_only_custom",
            ),
        ),
        migrations.AddConstraint(
            model_name="authzroledefinition",
            constraint=models.CheckConstraint(
                condition=models.Q(
                    models.Q(("definition_kind", "user_defined"), ("role_id__startswith", "custom_")),
                    models.Q(
                        ("definition_kind", "static"),
                        models.Q(("role_id__startswith", "custom_"), _negated=True),
                    ),
                    _connector="OR",
                ),
                name="authz_role_kind_matches_id_prefix",
            ),
        ),
    ]

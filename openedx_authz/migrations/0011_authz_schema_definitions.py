"""Compiled authorization definitions and source-tracking tables (ADR 0024)."""

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("openedx_authz", "0010_scope_external_key"),
    ]

    operations = [
        migrations.CreateModel(
            name="AuthzSchemaSource",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                (
                    "distribution",
                    models.CharField(
                        help_text="Installed distribution that shipped the contribution (e.g. 'openedx-authz').",
                        max_length=255,
                    ),
                ),
                (
                    "module",
                    models.CharField(
                        help_text="Python module that owns the schema resource (e.g. 'openedx_authz.authz').",
                        max_length=255,
                    ),
                ),
                ("distribution_version", models.CharField(blank=True, default="", max_length=64)),
                (
                    "resource_path",
                    models.CharField(
                        blank=True,
                        default="",
                        help_text="Latest-seen resource path within the module. Non-identifying.",
                        max_length=255,
                    ),
                ),
                ("content_digest", models.CharField(blank=True, default="", max_length=64)),
                ("schema_version", models.CharField(blank=True, default="", max_length=16)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={
                "verbose_name": "Authz Schema Source",
                "verbose_name_plural": "Authz Schema Sources",
            },
        ),
        migrations.CreateModel(
            name="AuthzPermissionCategory",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("category_id", models.CharField(max_length=255, unique=True)),
                ("display_name", models.CharField(max_length=255)),
                ("description", models.TextField(blank=True, default="")),
                ("icon", models.CharField(blank=True, max_length=128, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={
                "verbose_name": "Authz Permission Category",
                "verbose_name_plural": "Authz Permission Categories",
            },
        ),
        migrations.CreateModel(
            name="AuthzPermissionDefinition",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("namespace", models.CharField(max_length=255)),
                ("name", models.CharField(max_length=255)),
                ("display_name", models.CharField(max_length=255)),
                ("description", models.TextField(blank=True, default="")),
                ("scopes", models.JSONField(default=list)),
                ("icon", models.CharField(blank=True, max_length=128, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "category",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="permissions",
                        to="openedx_authz.authzpermissioncategory",
                    ),
                ),
            ],
            options={
                "verbose_name": "Authz Permission Definition",
                "verbose_name_plural": "Authz Permission Definitions",
            },
        ),
        migrations.CreateModel(
            name="AuthzRoleDefinition",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("role_id", models.CharField(max_length=255, unique=True)),
                ("display_name", models.CharField(max_length=255)),
                ("description", models.TextField(blank=True, default="")),
                ("scopes", models.JSONField(default=list)),
                ("icon", models.CharField(blank=True, max_length=128, null=True)),
                ("hidden", models.BooleanField(default=False)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={
                "verbose_name": "Authz Role Definition",
                "verbose_name_plural": "Authz Role Definitions",
            },
        ),
        migrations.CreateModel(
            name="AuthzRolePermission",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                (
                    "scope",
                    models.CharField(
                        help_text="Scope namespace where the grant applies (e.g. 'course-v1', 'lib').",
                        max_length=255,
                    ),
                ),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "permission",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="role_permissions",
                        to="openedx_authz.authzpermissiondefinition",
                    ),
                ),
                (
                    "role",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="role_permissions",
                        to="openedx_authz.authzroledefinition",
                    ),
                ),
            ],
            options={
                "verbose_name": "Authz Role Permission",
                "verbose_name_plural": "Authz Role Permissions",
            },
        ),
        migrations.CreateModel(
            name="AuthzCategorySource",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                (
                    "origin_kind",
                    models.CharField(
                        choices=[("base", "Base"), ("extension", "Extension")], default="base", max_length=16
                    ),
                ),
                ("priority", models.IntegerField(default=0)),
                (
                    "category",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE, to="openedx_authz.authzpermissioncategory"
                    ),
                ),
                (
                    "source",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE, to="openedx_authz.authzschemasource"
                    ),
                ),
            ],
            options={
                "verbose_name": "Authz Category Source",
                "verbose_name_plural": "Authz Category Sources",
            },
        ),
        migrations.CreateModel(
            name="AuthzPermissionSource",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                (
                    "origin_kind",
                    models.CharField(
                        choices=[("base", "Base"), ("extension", "Extension")], default="base", max_length=16
                    ),
                ),
                ("priority", models.IntegerField(default=0)),
                (
                    "permission",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE, to="openedx_authz.authzpermissiondefinition"
                    ),
                ),
                (
                    "source",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE, to="openedx_authz.authzschemasource"
                    ),
                ),
            ],
            options={
                "verbose_name": "Authz Permission Source",
                "verbose_name_plural": "Authz Permission Sources",
            },
        ),
        migrations.CreateModel(
            name="AuthzRoleSource",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                (
                    "origin_kind",
                    models.CharField(
                        choices=[("base", "Base"), ("extension", "Extension")], default="base", max_length=16
                    ),
                ),
                ("priority", models.IntegerField(default=0)),
                (
                    "role",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE, to="openedx_authz.authzroledefinition"
                    ),
                ),
                (
                    "source",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE, to="openedx_authz.authzschemasource"
                    ),
                ),
            ],
            options={
                "verbose_name": "Authz Role Source",
                "verbose_name_plural": "Authz Role Sources",
            },
        ),
        migrations.CreateModel(
            name="AuthzRolePermissionSource",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                (
                    "origin_kind",
                    models.CharField(
                        choices=[("base", "Base"), ("extension", "Extension")], default="base", max_length=16
                    ),
                ),
                ("priority", models.IntegerField(default=0)),
                (
                    "role_permission",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE, to="openedx_authz.authzrolepermission"
                    ),
                ),
                (
                    "source",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE, to="openedx_authz.authzschemasource"
                    ),
                ),
            ],
            options={
                "verbose_name": "Authz Role Permission Source",
                "verbose_name_plural": "Authz Role Permission Sources",
            },
        ),
        migrations.AddField(
            model_name="authzpermissioncategory",
            name="sources",
            field=models.ManyToManyField(
                related_name="categories",
                through="openedx_authz.AuthzCategorySource",
                to="openedx_authz.authzschemasource",
            ),
        ),
        migrations.AddField(
            model_name="authzpermissiondefinition",
            name="sources",
            field=models.ManyToManyField(
                related_name="permissions",
                through="openedx_authz.AuthzPermissionSource",
                to="openedx_authz.authzschemasource",
            ),
        ),
        migrations.AddField(
            model_name="authzroledefinition",
            name="sources",
            field=models.ManyToManyField(
                related_name="roles",
                through="openedx_authz.AuthzRoleSource",
                to="openedx_authz.authzschemasource",
            ),
        ),
        migrations.AddField(
            model_name="authzrolepermission",
            name="sources",
            field=models.ManyToManyField(
                related_name="role_permissions",
                through="openedx_authz.AuthzRolePermissionSource",
                to="openedx_authz.authzschemasource",
            ),
        ),
        migrations.AddConstraint(
            model_name="authzschemasource",
            constraint=models.UniqueConstraint(
                fields=["distribution", "module"], name="authz_source_dist_module_uniq"
            ),
        ),
        migrations.AddConstraint(
            model_name="authzpermissiondefinition",
            constraint=models.UniqueConstraint(fields=["namespace", "name"], name="authz_permission_ns_name_uniq"),
        ),
        migrations.AddConstraint(
            model_name="authzrolepermission",
            constraint=models.UniqueConstraint(
                fields=["role", "permission", "scope"], name="authz_role_permission_uniq"
            ),
        ),
        migrations.AddConstraint(
            model_name="authzcategorysource",
            constraint=models.UniqueConstraint(fields=["category", "source"], name="authz_category_source_uniq"),
        ),
        migrations.AddConstraint(
            model_name="authzpermissionsource",
            constraint=models.UniqueConstraint(
                fields=["permission", "source"], name="authz_permission_source_uniq"
            ),
        ),
        migrations.AddConstraint(
            model_name="authzrolesource",
            constraint=models.UniqueConstraint(fields=["role", "source"], name="authz_role_source_uniq"),
        ),
        migrations.AddConstraint(
            model_name="authzrolepermissionsource",
            constraint=models.UniqueConstraint(
                fields=["role_permission", "source"], name="authz_role_permission_source_uniq"
            ),
        ),
    ]

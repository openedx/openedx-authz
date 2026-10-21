"""Move persisted built-in schema ownership from the shared module to applets.

Released versions could load all built-in definitions from
``openedx_authz.authz.schema``, so installations that ran the schema loader may
have source links that still identify that shared module. The definitions now
live in applets, and this migration updates those persisted links so source
queries continue to report their current owners after an upgrade.

Installations without the shared source need no repair. Existing applet links
are also preserved because they may have been created by a previous schema
load or a partially completed deployment.
"""

from django.db import migrations

OLD_MODULE = "openedx_authz.authz.schema"
APPLET_MODULES = {
    "content_libraries": "openedx_authz.applets.content_libraries.schema",
    "course_authoring": "openedx_authz.applets.course_authoring.schema",
    "course_team_roles": "openedx_authz.applets.course_team_roles.schema",
}


def _category_owner(category_id):
    """Return the applet that owns a built-in permission category."""
    if category_id.startswith("library"):
        return "content_libraries"
    if category_id == "course_legacy":
        return "course_team_roles"
    return "course_authoring"


def _permission_owner(namespace, name):
    """Return the applet that owns a built-in permission."""
    if namespace == "content_libraries":
        return "content_libraries"
    if name.startswith("legacy_"):
        return "course_team_roles"
    return "course_authoring"


def _role_owner(role_id):
    """Return the applet that owns a built-in role."""
    if role_id.startswith("library_"):
        return "content_libraries"
    return "course_team_roles"


def _get_applet_source(source, owner):
    """Return the destination source for one applet, creating it when needed."""
    applet_source, _ = source.__class__.objects.get_or_create(
        distribution=source.distribution,
        module=APPLET_MODULES[owner],
        defaults={
            "distribution_version": source.distribution_version,
            "schema_version": source.schema_version,
        },
    )
    return applet_source


def _move_link(link, source, link_model, owner_field, owner):
    """Copy one source relationship to its applet source and remove the old link."""
    applet_source = _get_applet_source(source, owner)
    link_model.objects.get_or_create(
        **{owner_field: getattr(link, owner_field), "source": applet_source},
        defaults={"origin_kind": link.origin_kind, "priority": link.priority},
    )
    link.delete()


def move_builtin_schema_sources(apps, _schema_editor):
    """Redistribute released built-in source links among their owning applets."""
    Source = apps.get_model("openedx_authz", "AuthzSchemaSource")
    old_sources = Source.objects.filter(module=OLD_MODULE)
    if not old_sources.exists():
        return

    CategorySource = apps.get_model("openedx_authz", "AuthzCategorySource")
    PermissionSource = apps.get_model("openedx_authz", "AuthzPermissionSource")
    RoleSource = apps.get_model("openedx_authz", "AuthzRoleSource")
    RolePermissionSource = apps.get_model("openedx_authz", "AuthzRolePermissionSource")

    for source in old_sources:
        for link in list(CategorySource.objects.filter(source=source).select_related("category")):
            _move_link(link, source, CategorySource, "category", _category_owner(link.category.category_id))
        for link in list(PermissionSource.objects.filter(source=source).select_related("permission")):
            owner = _permission_owner(link.permission.namespace, link.permission.name)
            _move_link(link, source, PermissionSource, "permission", owner)
        for link in list(RoleSource.objects.filter(source=source).select_related("role")):
            _move_link(link, source, RoleSource, "role", _role_owner(link.role.role_id))
        for link in list(
            RolePermissionSource.objects.filter(source=source).select_related("role_permission__permission")
        ):
            permission = link.role_permission.permission
            owner = _permission_owner(permission.namespace, permission.name)
            _move_link(link, source, RolePermissionSource, "role_permission", owner)
        source.delete()


class Migration(migrations.Migration):
    """Move persisted built-in schema ownership to the applet modules."""

    dependencies = [
        ("openedx_authz", "0011_authz_schema_definitions"),
    ]

    operations = [
        migrations.RunPython(move_builtin_schema_sources, migrations.RunPython.noop),
    ]

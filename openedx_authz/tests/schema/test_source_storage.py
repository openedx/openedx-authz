"""Tests for persisting compiled definitions and their sources (ADR 0024).

These exercise ``SchemaApplier._store_sources`` directly (it performs only ORM
upserts, no enforcer access) plus the origin query helpers. The full ``apply``
path (enforcer + p rows) is covered by the engine tests.
"""

from django.test import TestCase

from openedx_authz.engine.renderer import SchemaApplier
from openedx_authz.engine.schema.compilation import SchemaCompiler
from openedx_authz.models.schema import (
    AuthzPermissionDefinition,
    AuthzRoleDefinition,
    AuthzRolePermission,
    AuthzRolePermissionSource,
    AuthzSchemaSource,
    OriginKind,
    origin_for_role_permission,
    origins_for_permission,
    origins_for_role,
)

from .factories import category, extension, make_document, permission, role

CORE_PERMS = [
    permission(name="view_course", cat="cat"),
    permission(name="manage_tags", cat="cat"),
    permission(name="export_course", cat="cat"),
]


def _core_doc():
    return make_document(
        "core",
        priority=100,
        categories=[category("cat")],
        permissions=CORE_PERMS,
        roles=[role(rid="course_admin", permissions=("courses.view_course", "courses.manage_tags"))],
    )


def _module_extension_doc():
    return make_document(
        "modx",
        priority=200,
        role_extensions=[extension("course_admin", add_permissions=("courses.export_course",))],
    )


def _store(*documents):
    schema = SchemaCompiler().compile(list(documents))
    SchemaApplier()._store_sources(schema)  # pylint: disable=protected-access
    return schema


class StoreSourcesTests(TestCase):
    """Persistence of compiled definitions and their provenance."""

    def test_definitions_are_persisted(self):
        _store(_core_doc())
        self.assertEqual(AuthzRoleDefinition.objects.count(), 1)
        self.assertEqual(AuthzPermissionDefinition.objects.count(), 3)
        role_obj = AuthzRoleDefinition.objects.get(role_id="course_admin")
        # course_admin has 2 permissions x 1 scope = 2 grants.
        self.assertEqual(role_obj.role_permissions.count(), 2)

    def test_source_identity_is_distribution_and_module(self):
        _store(_core_doc())
        source = AuthzSchemaSource.objects.get()
        self.assertEqual(source.distribution, "test-dist")
        self.assertEqual(source.module, "pkg.core")

    def test_extension_grant_attributed_to_module_not_core(self):
        _store(_core_doc(), _module_extension_doc())

        # Both grants live on course_admin, with distinct origins.
        self.assertEqual(origin_for_role_permission("course_admin", "courses.view_course"), ["test-dist"])
        self.assertEqual(origin_for_role_permission("course_admin", "courses.export_course"), ["test-dist"])

        export_grant = AuthzRolePermission.objects.get(
            role__role_id="course_admin", permission__namespace="courses", permission__name="export_course"
        )
        link = AuthzRolePermissionSource.objects.get(role_permission=export_grant)
        self.assertEqual(link.origin_kind, OriginKind.EXTENSION)
        self.assertEqual(link.priority, 200)

        view_grant = AuthzRolePermission.objects.get(
            role__role_id="course_admin", permission__name="view_course"
        )
        view_link = AuthzRolePermissionSource.objects.get(role_permission=view_grant)
        self.assertEqual(view_link.origin_kind, OriginKind.BASE)

    def test_origin_query_helpers(self):
        _store(_core_doc(), _module_extension_doc())
        self.assertEqual(origins_for_role("course_admin"), ["test-dist"])
        self.assertEqual(origins_for_permission("courses.export_course"), ["test-dist"])

    def test_store_is_idempotent(self):
        _store(_core_doc(), _module_extension_doc())
        counts = (
            AuthzRoleDefinition.objects.count(),
            AuthzPermissionDefinition.objects.count(),
            AuthzRolePermission.objects.count(),
            AuthzRolePermissionSource.objects.count(),
            AuthzSchemaSource.objects.count(),
        )
        _store(_core_doc(), _module_extension_doc())
        counts_again = (
            AuthzRoleDefinition.objects.count(),
            AuthzPermissionDefinition.objects.count(),
            AuthzRolePermission.objects.count(),
            AuthzRolePermissionSource.objects.count(),
            AuthzSchemaSource.objects.count(),
        )
        self.assertEqual(counts, counts_again)

    def test_metadata_change_updates_in_place(self):
        _store(_core_doc())
        changed = make_document(
            "core",
            priority=100,
            categories=[category("cat")],
            permissions=CORE_PERMS,
            roles=[
                role(
                    rid="course_admin",
                    display_name="Course Administrator",
                    permissions=("courses.view_course", "courses.manage_tags"),
                )
            ],
        )
        _store(changed)
        self.assertEqual(AuthzRoleDefinition.objects.count(), 1)
        self.assertEqual(
            AuthzRoleDefinition.objects.get(role_id="course_admin").display_name, "Course Administrator"
        )

    def test_moving_definition_between_files_keeps_single_source(self):
        # Same module, different resource_path -> identity unchanged.
        doc_a = _core_doc()
        doc_b = make_document(
            "core",  # same module name -> same (distribution, module)
            priority=100,
            categories=[category("cat")],
            permissions=CORE_PERMS,
            roles=[role(rid="course_admin", permissions=("courses.view_course", "courses.manage_tags"))],
        )
        doc_b.source = doc_b.source.__class__(**{**doc_b.source.__dict__, "resource_path": "moved.authz.yaml"})
        _store(doc_a)
        _store(doc_b)
        self.assertEqual(AuthzSchemaSource.objects.count(), 1)

"""Tests for persisting compiled definitions and their sources (ADR 0025).

These exercise ``SchemaApplier._store_sources`` directly (it performs only ORM
upserts, no enforcer access) plus the origin query helpers. The full ``apply``
path (enforcer + p rows) is covered by the engine tests.
"""

from dataclasses import replace

from django.test import TestCase

from openedx_authz.engine.renderer import SchemaApplier
from openedx_authz.engine.schema.compilation import SchemaCompiler
from openedx_authz.models.schema import (
    AuthzPermissionCategory,
    AuthzPermissionDefinition,
    AuthzRoleDefinition,
    AuthzRolePermission,
    AuthzRolePermissionSource,
    AuthzRoleSource,
    AuthzSchemaSource,
    OriginKind,
    origin_for_role_permission,
    origins_for_category,
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


class SourceGranularityTests(TestCase):
    """Source identity is per module, not per file (ADR 0025 §2).

    ``resource_path`` and ``content_digest`` are explicitly non-identifying, so
    several files in one module collapse into a single source row. This is what
    lets a definition move between files without churn, and it means those two
    advisory fields hold whichever file was processed last.
    """

    @staticmethod
    def _same_module(name: str, resource_path: str, roles):
        """Build a document in module ``pkg.<name>`` with an explicit file path.

        Each file gets its own digest so the per-module collapse is observable.
        """
        document = make_document(name, priority=100, categories=[category("cat")], permissions=CORE_PERMS, roles=roles)
        document.source = replace(
            document.source, resource_path=resource_path, content_digest=f"digest-{resource_path}"
        )
        return document

    def test_multiple_files_in_one_module_share_one_source_row(self):
        roles_file = self._same_module("core", "roles.yaml", [role(rid="course_admin")])
        extra_file = self._same_module("core", "more_roles.yaml", [role(rid="course_auditor")])

        _store(roles_file, extra_file)

        self.assertEqual(AuthzSchemaSource.objects.count(), 1)
        self.assertEqual(AuthzRoleDefinition.objects.count(), 2)

    def test_advisory_fields_come_from_the_first_file_of_the_module(self):
        """Why the digest is advisory, not a change-detection signal.

        One source row covers the whole module, and the per-apply cache fills it
        from whichever of the module's files is processed first. So the stored
        ``resource_path``/``content_digest`` describe one file out of several and
        cannot represent the module's contents — change detection diffs compiled
        definitions instead (ADR 0025 §2).
        """
        roles_file = self._same_module("core", "roles.yaml", [role(rid="course_admin")])
        extra_file = self._same_module("core", "more_roles.yaml", [role(rid="course_auditor")])

        _store(roles_file, extra_file)

        source = AuthzSchemaSource.objects.get()
        self.assertEqual(source.resource_path, "roles.yaml")
        self.assertNotEqual(source.content_digest, extra_file.source.content_digest)

    def test_distinct_modules_get_distinct_source_rows(self):
        first = self._same_module("core", "roles.yaml", [role(rid="course_admin")])
        second = self._same_module("other", "roles.yaml", [role(rid="course_auditor")])

        _store(first, second)

        self.assertEqual(AuthzSchemaSource.objects.count(), 2)
        self.assertEqual(
            sorted(AuthzSchemaSource.objects.values_list("module", flat=True)), ["pkg.core", "pkg.other"]
        )

    def test_shared_definition_gains_a_link_per_contributing_module(self):
        """ADR 0025 §2: the many-to-many exists to represent shared ownership."""
        first = self._same_module("core", "roles.yaml", [role(rid="course_admin")])
        second = self._same_module("other", "roles.yaml", [role(rid="course_admin")])

        _store(first, second)

        role_obj = AuthzRoleDefinition.objects.get(role_id="course_admin")
        self.assertEqual(AuthzRoleSource.objects.filter(role=role_obj).count(), 2)

    def test_shared_grant_gains_a_source_link_per_module(self):
        admin = [role(rid="course_admin", permissions=("courses.view_course",))]
        first = self._same_module("core", "roles.yaml", admin)
        second = self._same_module("other", "roles.yaml", admin)

        _store(first, second)

        grant = AuthzRolePermission.objects.get(role__role_id="course_admin", permission__name="view_course")
        self.assertEqual(AuthzRolePermissionSource.objects.filter(role_permission=grant).count(), 2)
        self.assertEqual(sorted(origin_for_role_permission("course_admin", "courses.view_course")), ["test-dist"])

    def test_category_origins_are_queryable(self):
        _store(_core_doc())

        self.assertEqual(origins_for_category("cat"), ["test-dist"])

    def test_source_rows_survive_definition_pruning(self):
        """Sources are shared and carry no access, so they are never pruned."""
        _store(_core_doc())
        self.assertEqual(AuthzSchemaSource.objects.count(), 1)

        _store()

        self.assertEqual(AuthzRoleDefinition.objects.count(), 0)
        self.assertEqual(AuthzSchemaSource.objects.count(), 1)

    def test_hidden_flag_reaches_the_database(self):
        """ADR 0023 §1: ``hidden`` is compiled state that has to be persisted."""
        _store(self._same_module("core", "roles.yaml", [role(rid="course_auditor", hidden=True)]))

        self.assertTrue(AuthzRoleDefinition.objects.get(role_id="course_auditor").hidden)

    def test_hidden_flag_can_be_cleared(self):
        _store(self._same_module("core", "roles.yaml", [role(rid="course_auditor", hidden=True)]))

        _store(self._same_module("core", "roles.yaml", [role(rid="course_auditor", hidden=False)]))

        self.assertFalse(AuthzRoleDefinition.objects.get(role_id="course_auditor").hidden)


class DefinitionDisplayTests(TestCase):
    """Human-readable identifiers used by the Django admin fallback (ADR 0018 §7)."""

    def test_source_string_is_distribution_and_module_path(self):
        _store(_core_doc())

        source = AuthzSchemaSource.objects.get()
        self.assertEqual(source.source_id, "test-dist:pkg/core")
        self.assertEqual(str(source), "test-dist:pkg/core")

    def test_permission_string_is_its_complete_id(self):
        _store(_core_doc())

        perm = AuthzPermissionDefinition.objects.get(namespace="courses", name="view_course")
        self.assertEqual(perm.identifier, "courses.view_course")
        self.assertEqual(str(perm), "courses.view_course")

    def test_role_and_category_strings_are_their_stable_ids(self):
        _store(_core_doc())

        self.assertEqual(str(AuthzRoleDefinition.objects.get(role_id="course_admin")), "course_admin")
        self.assertEqual(str(AuthzPermissionCategory.objects.get(category_id="cat")), "cat")

    def test_grant_string_names_role_permission_and_scope(self):
        """Regression: this used to render the FK integers, not the identifiers."""
        _store(_core_doc())

        grant = AuthzRolePermission.objects.get(role__role_id="course_admin", permission__name="view_course")
        self.assertEqual(str(grant), "course_admin -> courses.view_course @ course-v1")


class DefensiveStorageTests(TestCase):
    """Paths guarded against states validation is expected to have rejected."""

    def test_grant_for_an_undefined_permission_is_skipped(self):
        """A role listing a permission with no definition writes no grant."""
        document = make_document(
            "core",
            priority=100,
            categories=[category("cat")],
            permissions=[],
            roles=[role(rid="course_admin", permissions=("courses.ghost",))],
        )

        _store(document)

        self.assertTrue(AuthzRoleDefinition.objects.filter(role_id="course_admin").exists())
        self.assertEqual(AuthzRolePermission.objects.count(), 0)

    def test_permission_with_an_unknown_category_is_stored_uncategorized(self):
        document = make_document(
            "core",
            priority=100,
            categories=[],
            permissions=[permission(name="view_course", cat="missing")],
            roles=[],
        )

        _store(document)

        self.assertIsNone(AuthzPermissionDefinition.objects.get(name="view_course").category)

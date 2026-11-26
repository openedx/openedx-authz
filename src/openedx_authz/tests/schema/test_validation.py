"""Unit tests for the schema validation step.

Grouped by concern: per-document validation, duplicate severity, identifier and
scope rules, required fields, extension references, and post-compile validation.
"""

import pytest

from openedx_authz.engine.schema.compilation import SchemaCompiler
from openedx_authz.engine.schema.paragon_icons import PARAGON_ICON_NAMES
from openedx_authz.engine.schema.types import SchemaDocument
from openedx_authz.engine.schema.validation import SchemaValidator

from .factories import category, extension, make_document, make_source, permission, role


def _errors(issues):
    return [i for i in issues if i.is_error]


def _warnings(issues):
    return [i for i in issues if not i.is_error]


class TestDocumentValidation:
    """Per-document ``validate`` checks (ADR 0017 §4).

    These run before compilation and see each document's own declarations, so
    they cover identifier shape, Casbin-form rejection, intra-document
    references (category, permission, role, scope), and duplicate conflicts.
    """

    def test_valid_document_has_no_errors(self):
        """A well-formed document produces no error issues."""
        doc = make_document(
            categories=[category("cat")],
            permissions=[permission(cat="cat")],
            roles=[role(permissions=("courses.view_course",))],
        )
        assert not _errors(SchemaValidator().validate([doc]))

    def test_unknown_category_reference_is_error(self):
        """A permission referencing a category not defined in the schema fails."""
        doc = make_document(permissions=[permission(cat="missing")])
        messages = [i.message for i in _errors(SchemaValidator().validate([doc]))]
        assert any("unknown category" in m for m in messages)

    def test_unknown_permission_in_role_is_error(self):
        """A role listing a permission that does not exist fails."""
        doc = make_document(roles=[role(permissions=("courses.nope",))])
        messages = [i.message for i in _errors(SchemaValidator().validate([doc]))]
        assert any("unknown permission" in m for m in messages)

    def test_role_scope_not_supported_by_permission_is_error(self):
        """A role cannot grant a permission outside the permission's scopes."""
        doc = make_document(
            categories=[category("cat")],
            permissions=[permission(cat="cat", scopes=("course-v1",))],
            roles=[role(rid="r", scopes=("lib",), permissions=("courses.view_course",))],
        )
        messages = [i.message for i in _errors(SchemaValidator().validate([doc]))]
        assert any("does not support" in m for m in messages)

    def test_extension_targeting_unknown_role_is_error(self):
        """An extension for a role absent from the same document fails here."""
        doc = make_document(role_extensions=[extension("ghost", add_permissions=("courses.view_course",))])
        messages = [i.message for i in _errors(SchemaValidator().validate([doc]))]
        assert any("unknown role" in m for m in messages)

    def test_role_without_base_permissions_warns(self):
        """An empty base permission list is accepted but reported."""
        doc = make_document("roles", roles=[role(rid="course_editor", permissions=())])

        issues = SchemaValidator().validate([doc])

        assert not _errors(issues)
        assert any("role 'course_editor' declares no base permissions" in i.message for i in _warnings(issues))
        assert [i.source_id for i in _warnings(issues)] == [make_source("roles").source_id]

    def test_conflicting_duplicate_definition_is_error(self):
        """Two definitions with the same id but different content conflict."""
        doc = make_document(
            categories=[category("cat")],
            permissions=[
                permission(cat="cat", display_name="One"),
                permission(cat="cat", display_name="Two"),  # same id, different content
            ],
        )
        messages = [i.message for i in _errors(SchemaValidator().validate([doc]))]
        assert any("Conflicting permission" in m for m in messages)


class TestReservedRoleIdPrefix:
    """Static role IDs cannot use the prefix reserved for custom roles (ADR 0035)."""

    @staticmethod
    def _document(role_id: str, name: str = "doc") -> SchemaDocument:
        """Build a valid document that declares one role with the given ID."""
        return make_document(
            name,
            categories=[category("cat")],
            permissions=[permission(cat="cat")],
            roles=[role(rid=role_id, permissions=("courses.view_course",))],
        )

    def test_static_role_with_reserved_prefix_is_error(self):
        """A static role whose ID starts with ``custom_`` fails validation."""
        errors = _errors(SchemaValidator().validate([self._document("custom_designer")]))

        assert [error.message for error in errors] == [
            "Role 'custom_designer' uses the 'custom_' prefix, which is reserved for custom roles."
        ]

    def test_error_names_the_contributing_source(self):
        """The error carries the source of the document that declares the role."""
        document = self._document("custom_designer", name="plugin")

        (error,) = _errors(SchemaValidator().validate([document]))

        assert error.source_id == document.source.source_id

    def test_prefix_is_only_reserved_at_the_start_of_the_id(self):
        """A role that merely contains ``custom`` is valid."""
        assert not _errors(SchemaValidator().validate([self._document("course_custom_editor")]))


class TestDuplicateSeverity:
    """ADR 0017 §4 splits duplicates by severity: identical warns, differing fails."""

    def test_identical_duplicate_warns_instead_of_failing(self):
        """Two packages shipping the same definition is legal, not an error."""
        first = make_document("first", categories=[category("cat")])
        second = make_document("second", categories=[category("cat")])

        issues = SchemaValidator().validate([first, second])

        assert not _errors(issues)
        assert any("Duplicate identical category" in i.message for i in _warnings(issues))

    def test_identical_duplicate_role_warns(self):
        """Two identical role definitions warn rather than error."""
        first = make_document("first", roles=[role()])
        second = make_document("second", roles=[role()])

        issues = SchemaValidator().validate([first, second])

        assert any("Duplicate identical role" in i.message for i in _warnings(issues))

    def test_conflicting_duplicate_role_is_error(self):
        """Two role definitions with the same id but different content conflict."""
        first = make_document("first", roles=[role(display_name="Editor")])
        second = make_document("second", roles=[role(display_name="Author")])

        messages = [i.message for i in _errors(SchemaValidator().validate([first, second]))]

        assert any("Conflicting role definition" in m for m in messages)

    def test_permission_defined_with_different_dependencies_is_error(self):
        """Only the defining file declares dependencies, so two files that disagree conflict (ADR 0034 §5)."""
        first = make_document(
            "first", categories=[category("cat")], permissions=[permission(depends_on=("courses.view_course_team",))]
        )
        second = make_document("second", permissions=[permission(depends_on=("courses.view_course_updates",))])

        messages = [i.message for i in _errors(SchemaValidator().validate([first, second]))]

        assert any("Conflicting permission definition for 'courses.view_course'" in m for m in messages)

    def test_1_0_duplicate_of_a_permission_with_dependencies_is_error(self):
        """A 1.0 file cannot declare ``depends_on``, so it cannot repeat a 1.1 definition that does."""
        v1_0 = make_document("v1_0", categories=[category("cat")], permissions=[permission()])
        v1_1 = make_document(
            "v1_1", schema_version="1.1", permissions=[permission(depends_on=("courses.view_course_team",))]
        )

        messages = [i.message for i in _errors(SchemaValidator().validate([v1_0, v1_1]))]

        assert any("Conflicting permission definition" in m for m in messages)

    def test_identical_dependencies_are_an_identical_duplicate(self):
        """Two files that define a permission with the same dependencies only warn."""
        first = make_document(
            "first", categories=[category("cat")], permissions=[permission(depends_on=("courses.view_course_team",))]
        )
        second = make_document("second", permissions=[permission(depends_on=("courses.view_course_team",))])

        issues = SchemaValidator().validate([first, second])

        assert not any("Conflicting" in i.message for i in _errors(issues))
        assert any("Duplicate identical permission" in i.message for i in _warnings(issues))

    def test_warning_names_the_second_source(self):
        """The duplicate warning is attributed to the later contributing source."""
        first = make_document("first", categories=[category("cat")])
        second = make_document("second", categories=[category("cat")])

        issues = _warnings(SchemaValidator().validate([first, second]))

        assert [i.source_id for i in issues] == [make_source("second").source_id]


class TestExtensionReferences:
    """ADR 0023 §3: an extension must target a real role and real permissions."""

    def test_added_permission_must_exist(self):
        """An extension that adds a nonexistent permission is an error."""
        doc = make_document(
            categories=[category("cat")],
            permissions=[permission(cat="cat")],
            roles=[role()],
            role_extensions=[extension("course_editor", add_permissions=("courses.ghost",))],
        )

        messages = [i.message for i in _errors(SchemaValidator().validate([doc]))]

        assert any("references unknown permission 'courses.ghost'" in m for m in messages)

    def test_removed_permission_must_exist(self):
        """An extension that removes a nonexistent permission is an error."""
        doc = make_document(
            categories=[category("cat")],
            permissions=[permission(cat="cat")],
            roles=[role()],
            role_extensions=[extension("course_editor", remove_permissions=("courses.ghost",))],
        )

        messages = [i.message for i in _errors(SchemaValidator().validate([doc]))]

        assert any("references unknown permission 'courses.ghost'" in m for m in messages)

    def test_extension_may_target_a_role_from_another_document(self):
        """An extension may target a role defined in a different document."""
        base = make_document(
            "base",
            categories=[category("cat")],
            permissions=[permission(cat="cat")],
            roles=[role()],
        )
        ext = make_document("ext", role_extensions=[extension("course_editor", display_name="Author")])

        assert not _errors(SchemaValidator().validate([base, ext]))


class TestValidateCompiled:
    """Post-compile rules that only the resolved schema can answer.

    Document-level validation sees base declarations only, so these cases pass
    ``validate`` and must be caught by ``validate_compiled``.
    """

    @staticmethod
    def _compile(*documents):
        return SchemaCompiler().compile(list(documents))

    def test_extension_added_permission_must_support_role_scopes(self):
        """An extension cannot grant a permission outside the role's scopes.

        Regression test: ``course_editor`` is a ``course-v1`` role, the added
        permission only applies to ``lib``, yet document validation is clean
        because it never inspects the extension's effect (ADR 0017 §4).
        """
        base = make_document(
            "base",
            priority=100,
            categories=[category("cat")],
            permissions=[
                permission(cat="cat", scopes=("course-v1",)),
                permission("libraries", "edit_library", cat="cat", scopes=("lib",)),
            ],
            roles=[role(rid="course_editor", scopes=("course-v1",), permissions=("courses.view_course",))],
        )
        ext = make_document(
            "ext",
            priority=200,
            role_extensions=[extension("course_editor", add_permissions=("libraries.edit_library",))],
        )
        validator = SchemaValidator()
        assert not _errors(validator.validate([base, ext]))

        messages = [i.message for i in _errors(validator.validate_compiled(self._compile(base, ext)))]

        assert any("libraries.edit_library" in m and "does not support" in m for m in messages)

    def test_error_names_the_extending_source(self):
        """The operator needs the extending file's id, not the role's file."""
        base = make_document(
            "base",
            priority=100,
            categories=[category("cat")],
            permissions=[
                permission(cat="cat", scopes=("course-v1",)),
                permission("libraries", "edit_library", cat="cat", scopes=("lib",)),
            ],
            roles=[role(rid="course_editor", scopes=("course-v1",), permissions=("courses.view_course",))],
        )
        ext = make_document(
            "ext",
            priority=200,
            role_extensions=[extension("course_editor", add_permissions=("libraries.edit_library",))],
        )

        issues = _errors(SchemaValidator().validate_compiled(self._compile(base, ext)))

        assert [i.source_id for i in issues] == [make_source("ext").source_id]

    def test_no_error_when_extension_permission_shares_the_role_scope(self):
        """Negative control: the rule must not fire on a compatible extension."""
        base = make_document(
            "base",
            priority=100,
            categories=[category("cat")],
            permissions=[
                permission(cat="cat", scopes=("course-v1",)),
                permission("courses", "export_course", cat="cat", scopes=("course-v1",)),
            ],
            roles=[role(rid="course_editor", scopes=("course-v1",), permissions=("courses.view_course",))],
        )
        ext = make_document(
            "ext",
            priority=200,
            role_extensions=[extension("course_editor", add_permissions=("courses.export_course",))],
        )

        assert not _errors(SchemaValidator().validate_compiled(self._compile(base, ext)))

    def test_multi_scope_permission_supports_a_narrower_role(self):
        """A permission may support more scopes than the role uses."""
        doc = make_document(
            categories=[category("cat")],
            permissions=[permission(cat="cat", scopes=("course-v1", "lib"))],
            roles=[role(rid="course_editor", scopes=("course-v1",), permissions=("courses.view_course",))],
        )

        assert not _errors(SchemaValidator().validate_compiled(self._compile(doc)))

    def test_compiled_permission_with_unknown_category_is_error(self):
        """Defensive: a category that vanished during resolution is reported."""
        doc = make_document(
            permissions=[permission(cat="missing")],
        )

        messages = [i.message for i in _errors(SchemaValidator().validate_compiled(self._compile(doc)))]

        assert any("unknown category" in m for m in messages)

    def test_valid_schema_has_no_compiled_errors(self):
        """A well-formed compiled schema produces no post-compile errors."""
        doc = make_document(
            categories=[category("cat")],
            permissions=[permission(cat="cat")],
            roles=[role(permissions=("courses.view_course",))],
        )

        assert not _errors(SchemaValidator().validate_compiled(self._compile(doc)))

    def test_compiled_role_referencing_a_missing_permission_is_error(self):
        """Defensive: a permission definition that never made it into the schema."""
        doc = make_document(roles=[role(permissions=("courses.ghost",))])

        messages = [i.message for i in _errors(SchemaValidator().validate_compiled(self._compile(doc)))]

        assert any("resolves to unknown permission 'courses.ghost'" in m for m in messages)

    def test_source_id_is_omitted_when_provenance_is_missing(self):
        """A grant with no recorded provenance still produces a usable issue."""
        doc = make_document(roles=[role(permissions=("courses.ghost",))])
        schema = self._compile(doc)
        schema.role_permission_sources.clear()

        issues = _errors(SchemaValidator().validate_compiled(schema))

        assert [i.source_id for i in issues] == [None]


def lib_permission(name, *, depends_on=(), scopes=("lib",)):
    """Build a content library permission for dependency tests."""
    return permission("content_libraries", name, cat="cat", scopes=scopes, depends_on=depends_on)


LIB_VIEW = "content_libraries.view_library"
LIB_EDIT = "content_libraries.edit_library_content"
LIB_TAGS = "content_libraries.manage_library_tags"

LIBRARY_PERMISSIONS = [
    lib_permission("view_library"),
    lib_permission("edit_library_content", depends_on=(LIB_VIEW,)),
    lib_permission("manage_library_tags", depends_on=(LIB_EDIT,)),
]


class TestPermissionDependencyRules:
    """Whole-set checks on ``depends_on`` entries (ADR 0034 §3)."""

    @staticmethod
    def _messages(*permissions):
        """Return the whole-set errors for one 1.1 file that defines the given permissions."""
        document = make_document(
            "perms", schema_version="1.1", categories=[category("cat")], permissions=list(permissions)
        )
        return [i.message for i in _errors(SchemaValidator().validate([document]))]

    def test_valid_dependencies_pass(self):
        """Dependencies on defined permissions with covering scopes and no cycle are valid."""
        assert not self._messages(*LIBRARY_PERMISSIONS)

    def test_dependency_on_an_undefined_permission_is_error(self):
        """A dependency must reference a permission defined in the combined schema."""
        messages = self._messages(lib_permission("edit_library_content", depends_on=(LIB_VIEW,)))

        assert messages == [f"Permission {LIB_EDIT} depends on unknown permission '{LIB_VIEW}'."]

    def test_dependency_defined_in_another_file_is_valid(self):
        """Dependencies resolve across files, like role permissions do."""
        first = make_document("first", categories=[category("cat")], permissions=[lib_permission("view_library")])
        second = make_document(
            "second", schema_version="1.1", permissions=[lib_permission("edit_library_content", depends_on=(LIB_VIEW,))]
        )

        assert not _errors(SchemaValidator().validate([first, second]))

    def test_self_dependency_is_error(self):
        """A permission cannot depend on itself."""
        messages = self._messages(lib_permission("view_library", depends_on=(LIB_VIEW,)))

        assert messages == [f"Permission {LIB_VIEW} depends on itself."]

    def test_dependency_cycle_is_error(self):
        """Permissions that depend on each other, directly or through others, are rejected once."""
        messages = self._messages(
            lib_permission("view_library", depends_on=(LIB_TAGS,)),
            lib_permission("edit_library_content", depends_on=(LIB_VIEW,)),
            lib_permission("manage_library_tags", depends_on=(LIB_EDIT,)),
        )

        assert messages == [
            f"Permissions form a dependency cycle: {LIB_EDIT} -> {LIB_VIEW} -> {LIB_TAGS} -> {LIB_EDIT}."
        ]

    def test_dependency_must_support_every_scope_of_the_dependent_permission(self):
        """A dependency granted in fewer scopes would leave the permission unusable in the others."""
        messages = self._messages(
            lib_permission("view_library", scopes=("lib",)),
            lib_permission("edit_library_content", depends_on=(LIB_VIEW,), scopes=("lib", "course-v1")),
        )

        assert messages == [
            f"Permission {LIB_EDIT} supports scope(s) ['course-v1'] that its dependency '{LIB_VIEW}' does not support."
        ]

    def test_dependency_may_support_more_scopes(self):
        """Only the dependent permission's scopes must be covered."""
        assert not self._messages(
            lib_permission("view_library", scopes=("lib", "course-v1")),
            lib_permission("edit_library_content", depends_on=(LIB_VIEW,), scopes=("lib",)),
        )

    def test_error_names_the_file_that_defines_the_permission(self):
        """Dependency errors point at the file that declares ``depends_on``."""
        first = make_document("first", categories=[category("cat")], permissions=[lib_permission("view_library")])
        second = make_document(
            "second", schema_version="1.1", permissions=[lib_permission("edit_library_content", depends_on=(LIB_TAGS,))]
        )

        issues = _errors(SchemaValidator().validate([first, second]))

        assert [i.source_id for i in issues] == [make_source("second").source_id]


class TestRoleDependencyRule:
    """A role must list every dependency of the permissions it grants (ADR 0034 §3).

    The rule runs on the compiled schema, so it sees the effect of role extensions.
    """

    @staticmethod
    def _messages(*documents):
        schema = SchemaCompiler().compile(list(documents))
        return [i.message for i in _errors(SchemaValidator().validate_compiled(schema))]

    @staticmethod
    def _base(role_permissions, *, schema_version="1.1"):
        return make_document(
            "base",
            schema_version=schema_version,
            categories=[category("cat")],
            permissions=LIBRARY_PERMISSIONS,
            roles=[role(rid="library_author", scopes=("lib",), permissions=role_permissions)],
        )

    def test_role_with_every_dependency_passes(self):
        """Listing direct and indirect dependencies satisfies the rule."""
        assert not self._messages(self._base((LIB_VIEW, LIB_EDIT, LIB_TAGS)))

    def test_role_missing_a_direct_dependency_is_error(self):
        """A role cannot grant a permission without the permissions it depends on."""
        messages = self._messages(self._base((LIB_EDIT,)))

        assert messages == [
            f"Role library_author grants permission '{LIB_EDIT}' without its dependencies ['{LIB_VIEW}']. "
            "Add them to the role, or keep role_extensions from removing them."
        ]

    def test_role_missing_an_indirect_dependency_is_error(self):
        """Indirect dependencies count: ``manage_library_tags`` also needs ``view_library``."""
        messages = self._messages(self._base((LIB_EDIT, LIB_TAGS)))

        assert len(messages) == 2
        assert all(f"['{LIB_VIEW}']" in message for message in messages)

    def test_extension_that_adds_a_permission_without_its_dependencies_is_error(self):
        """An extension's additions are checked against the role's resolved permissions."""
        ext = make_document(
            "ext", priority=200, role_extensions=[extension("library_author", add_permissions=(LIB_TAGS,))]
        )

        messages = self._messages(self._base((LIB_VIEW,)), ext)

        assert len(messages) == 1
        assert f"'{LIB_TAGS}' without its dependencies ['{LIB_EDIT}']" in messages[0]

    def test_extension_that_adds_the_dependencies_too_passes(self):
        """An extension can satisfy the rule by adding the dependencies it needs."""
        ext = make_document(
            "ext", priority=200, role_extensions=[extension("library_author", add_permissions=(LIB_EDIT, LIB_TAGS))]
        )

        assert not self._messages(self._base((LIB_VIEW,)), ext)

    def test_extension_cannot_remove_a_dependency_another_permission_needs(self):
        """``remove_permissions`` cannot drop ``view_library`` while the role keeps ``edit_library_content``."""
        ext = make_document(
            "ext", priority=200, role_extensions=[extension("library_author", remove_permissions=(LIB_VIEW,))]
        )

        messages = self._messages(self._base((LIB_VIEW, LIB_EDIT)), ext)

        assert len(messages) == 1
        assert f"'{LIB_EDIT}' without its dependencies ['{LIB_VIEW}']" in messages[0]

    def test_extension_that_removes_a_permission_and_its_dependents_passes(self):
        """Removing a dependency together with every permission that needs it keeps the role complete."""
        ext = make_document(
            "ext", priority=200, role_extensions=[extension("library_author", remove_permissions=(LIB_VIEW, LIB_EDIT))]
        )

        assert not self._messages(self._base((LIB_VIEW, LIB_EDIT)), ext)

    def test_1_0_role_file_is_checked_against_dependencies_from_a_1_1_file(self):
        """The rule applies to roles in every file, whatever ``schema_version`` it declares."""
        permissions = make_document(
            "permissions", schema_version="1.1", categories=[category("cat")], permissions=LIBRARY_PERMISSIONS
        )
        roles = make_document(
            "roles",
            schema_version="1.0",
            roles=[role(rid="library_author", scopes=("lib",), permissions=(LIB_EDIT,))],
        )

        messages = self._messages(permissions, roles)

        assert len(messages) == 1
        assert f"'{LIB_EDIT}' without its dependencies ['{LIB_VIEW}']" in messages[0]

    def test_error_names_the_file_that_grants_the_permission(self):
        """The issue points at the file that grants the incomplete permission, here an extension."""
        ext = make_document(
            "ext", priority=200, role_extensions=[extension("library_author", add_permissions=(LIB_TAGS,))]
        )

        issues = _errors(SchemaValidator().validate_compiled(SchemaCompiler().compile([self._base((LIB_VIEW,)), ext])))

        assert [i.source_id for i in issues] == [make_source("ext").source_id]

    def test_hidden_role_is_checked_too(self):
        """Hiding a role does not change what it grants, so the rule still applies."""
        document = make_document(
            "base",
            schema_version="1.1",
            categories=[category("cat")],
            permissions=LIBRARY_PERMISSIONS,
            roles=[role(rid="library_author", scopes=("lib",), permissions=(LIB_EDIT,), hidden=True)],
        )

        assert self._messages(document)


class TestVisibleDependencyRule:
    """A visible permission cannot depend on a hidden one (ADR 0038)."""

    @staticmethod
    def _issues(permissions, categories=(category("cat"), category("internal", hidden=True))):
        document = make_document("base", schema_version="1.1", categories=list(categories), permissions=permissions)
        return _errors(SchemaValidator().validate_compiled(SchemaCompiler().compile([document])))

    def test_visible_permission_depending_on_hidden_permission_is_error(self):
        """A visible permission cannot depend on a permission that sets ``hidden: true``."""
        issues = self._issues(
            [
                permission("content_libraries", "view_library", scopes=("lib",), hidden=True),
                lib_permission("edit_library_content", depends_on=(LIB_VIEW,)),
            ]
        )

        assert [i.message for i in issues] == [
            f"Visible permission {LIB_EDIT} depends on hidden permission(s) ['{LIB_VIEW}']. "
            "Hide the permission too, or make its dependencies visible."
        ]
        assert issues[0].source_id == make_source("base").source_id

    def test_dependency_in_hidden_category_is_error(self):
        """A visible permission cannot depend on a permission whose category is hidden."""
        issues = self._issues(
            [
                permission("content_libraries", "view_library", cat="internal", scopes=("lib",)),
                lib_permission("edit_library_content", depends_on=(LIB_VIEW,)),
            ]
        )

        assert len(issues) == 1
        assert f"['{LIB_VIEW}']" in issues[0].message

    def test_indirect_hidden_dependency_is_reported_on_the_direct_dependent(self):
        """In ``tags -> edit -> view (hidden)``, only ``edit`` directly depends on the hidden permission."""
        issues = self._issues(
            [
                permission("content_libraries", "view_library", scopes=("lib",), hidden=True),
                lib_permission("edit_library_content", depends_on=(LIB_VIEW,)),
                lib_permission("manage_library_tags", depends_on=(LIB_EDIT,)),
            ]
        )

        assert len(issues) == 1
        assert issues[0].message.startswith(f"Visible permission {LIB_EDIT} ")

    def test_hidden_permission_may_depend_on_hidden_or_visible_permissions(self):
        """Only visible permissions are constrained."""
        assert not self._issues(
            [
                lib_permission("view_library"),
                permission(
                    "content_libraries", "edit_library_content", scopes=("lib",), hidden=True, depends_on=(LIB_VIEW,)
                ),
                permission(
                    "content_libraries", "manage_library_tags", cat="internal", scopes=("lib",), depends_on=(LIB_EDIT,)
                ),
            ]
        )


class TestIconRules:
    """ADR 0017 §4: icon names must be valid @openedx/paragon/icons names."""

    # Pick a known-valid icon name dynamically instead of hardcoding a specific icon.
    # This makes the tests resilient if a future paragon upgrade removes the icon we
    # might have chosen. We use the first icon in the frozenset (sorted for stability).
    _VALID_ICON = sorted(PARAGON_ICON_NAMES)[0]

    def test_valid_category_icon_has_no_errors(self):
        """A real Paragon icon name on a category passes validation."""
        doc = make_document(categories=[category("cat", icon=self._VALID_ICON)])

        assert not _errors(SchemaValidator().validate([doc]))

    def test_valid_permission_icon_has_no_errors(self):
        """A real Paragon icon name on a permission passes validation."""
        doc = make_document(
            categories=[category("cat")],
            permissions=[permission(cat="cat", icon=self._VALID_ICON)],
        )

        assert not _errors(SchemaValidator().validate([doc]))

    def test_valid_role_icon_has_no_errors(self):
        """A real Paragon icon name on a role passes validation."""
        doc = make_document(roles=[role(icon=self._VALID_ICON)])

        assert not _errors(SchemaValidator().validate([doc]))

    def test_valid_role_extension_icon_has_no_errors(self):
        """A real Paragon icon name on a role_extension passes validation."""
        base = make_document(
            "base",
            categories=[category("cat")],
            permissions=[permission(cat="cat")],
            roles=[role()],
        )
        ext = make_document("ext", role_extensions=[extension("course_editor", icon=self._VALID_ICON)])

        assert not _errors(SchemaValidator().validate([base, ext]))

    @pytest.mark.parametrize("icon", [None, ""])
    def test_missing_icon_is_allowed(self, icon):
        """Icons are optional on every definition."""
        doc = make_document(categories=[category("cat", icon=icon)])

        assert not _errors(SchemaValidator().validate([doc]))

    def test_unknown_but_wellformed_icon_is_error(self):
        """A PascalCase name that Paragon does not export is rejected."""
        doc = make_document(categories=[category("cat", icon="NotARealParagonIcon")])

        messages = [i.message for i in _errors(SchemaValidator().validate([doc]))]

        assert any("is not a valid @openedx/paragon/icons name" in m for m in messages)

    def test_permission_icon_is_validated(self):
        """A permission's icon is validated and the error names the permission."""
        doc = make_document(
            categories=[category("cat")],
            permissions=[permission(cat="cat", icon="NotARealParagonIcon")],
        )

        messages = [i.message for i in _errors(SchemaValidator().validate([doc]))]

        assert any(
            "permission courses.view_course" in message and "not a valid @openedx/paragon/icons" in message
            for message in messages
        )

    def test_role_icon_is_validated(self):
        """A role's icon is validated and the error names the role."""
        doc = make_document(roles=[role(icon="NotARealParagonIcon")])

        messages = [i.message for i in _errors(SchemaValidator().validate([doc]))]

        assert any("role course_editor" in m and "not a valid @openedx/paragon/icons" in m for m in messages)

    def test_role_extension_icon_is_validated(self):
        """A role_extension may set an icon, so its value is checked too."""
        base = make_document(
            "base",
            categories=[category("cat")],
            permissions=[permission(cat="cat")],
            roles=[role()],
        )
        ext = make_document("ext", role_extensions=[extension("course_editor", icon="NotARealParagonIcon")])

        messages = [i.message for i in _errors(SchemaValidator().validate([base, ext]))]

        assert any("role_extension course_editor" in m for m in messages)

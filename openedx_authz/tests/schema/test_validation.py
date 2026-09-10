"""Unit tests for the schema validation step."""

import pytest

from openedx_authz.engine.schema.compilation import SchemaCompiler
from openedx_authz.engine.schema.validation import (
    ERROR,
    WARNING,
    SchemaValidator,
    ValidationIssue,
)

from .factories import category, extension, make_document, make_source, permission, role


def _errors(issues):
    return [i for i in issues if i.is_error]


def test_valid_document_has_no_errors():
    doc = make_document(
        categories=[category("cat")],
        permissions=[permission(cat="cat")],
        roles=[role(permissions=("courses.view_course",))],
    )
    assert not _errors(SchemaValidator().validate([doc]))


def test_unsupported_schema_version_is_error():
    doc = make_document(schema_version="9.9", categories=[category()])
    messages = [i.message for i in _errors(SchemaValidator().validate([doc]))]
    assert any("Unsupported schema_version" in m for m in messages)


def test_non_snakecase_identifier_is_error():
    doc = make_document(permissions=[permission(namespace="Courses")])
    assert _errors(SchemaValidator().validate([doc]))


def test_casbin_internal_form_rejected():
    doc = make_document(categories=[category("act^foo")])
    messages = [i.message for i in _errors(SchemaValidator().validate([doc]))]
    assert any("internal Casbin form" in m for m in messages)


def test_unknown_category_reference_is_error():
    doc = make_document(permissions=[permission(cat="missing")])
    messages = [i.message for i in _errors(SchemaValidator().validate([doc]))]
    assert any("unknown category" in m for m in messages)


def test_unknown_permission_in_role_is_error():
    doc = make_document(roles=[role(permissions=("courses.nope",))])
    messages = [i.message for i in _errors(SchemaValidator().validate([doc]))]
    assert any("unknown permission" in m for m in messages)


def test_role_scope_not_supported_by_permission_is_error():
    doc = make_document(
        categories=[category("cat")],
        permissions=[permission(cat="cat", scopes=("course-v1",))],
        roles=[role(rid="r", scopes=("lib",), permissions=("courses.view_course",))],
    )
    messages = [i.message for i in _errors(SchemaValidator().validate([doc]))]
    assert any("does not support" in m for m in messages)


def test_extension_targeting_unknown_role_is_error():
    doc = make_document(role_extensions=[extension("ghost", add_permissions=("courses.view_course",))])
    messages = [i.message for i in _errors(SchemaValidator().validate([doc]))]
    assert any("unknown role" in m for m in messages)


def test_missing_scope_is_error():
    doc = make_document(
        categories=[category("cat")],
        permissions=[permission(cat="cat", scopes=())],
    )
    messages = [i.message for i in _errors(SchemaValidator().validate([doc]))]
    assert any("at least one scope" in m for m in messages)


def test_conflicting_duplicate_definition_is_error():
    doc = make_document(
        categories=[category("cat")],
        permissions=[
            permission(cat="cat", display_name="One"),
            permission(cat="cat", display_name="Two"),  # same id, different content
        ],
    )
    messages = [i.message for i in _errors(SchemaValidator().validate([doc]))]
    assert any("Conflicting permission" in m for m in messages)


def _warnings(issues):
    return [i for i in issues if not i.is_error]


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
        first = make_document("first", roles=[role()])
        second = make_document("second", roles=[role()])

        issues = SchemaValidator().validate([first, second])

        assert any("Duplicate identical role" in i.message for i in _warnings(issues))

    def test_conflicting_duplicate_role_is_error(self):
        first = make_document("first", roles=[role(display_name="Editor")])
        second = make_document("second", roles=[role(display_name="Author")])

        messages = [i.message for i in _errors(SchemaValidator().validate([first, second]))]

        assert any("Conflicting role definition" in m for m in messages)

    def test_warning_names_the_second_source(self):
        first = make_document("first", categories=[category("cat")])
        second = make_document("second", categories=[category("cat")])

        issues = _warnings(SchemaValidator().validate([first, second]))

        assert [i.source_id for i in issues] == [make_source("second").source_id]


class TestIdentifierAndScopeRules:
    """Field-shape rules from ADR 0017 §4."""

    @pytest.mark.parametrize("value", ["courses", "courses.view.course", ""])
    def test_permission_id_must_be_namespace_dot_name(self, value):
        doc = make_document(roles=[role(permissions=(value,))])

        messages = [i.message for i in _errors(SchemaValidator().validate([doc]))]

        assert any("must be 'namespace.name'" in m for m in messages)

    def test_permission_id_halves_are_validated(self):
        doc = make_document(roles=[role(permissions=("Courses.View_Course",))])

        messages = [i.message for i in _errors(SchemaValidator().validate([doc]))]

        assert any("lowercase snake_case" in m for m in messages)

    @pytest.mark.parametrize("prefix", ["act^", "role^", "sub^", "scope^", "g^", "p^"])
    def test_every_casbin_prefix_is_rejected(self, prefix):
        doc = make_document(roles=[role(rid=f"{prefix}thing")])

        messages = [i.message for i in _errors(SchemaValidator().validate([doc]))]

        assert any("internal Casbin form" in m for m in messages)

    @pytest.mark.parametrize("scope", ["Course-V1", "1course", "course v1", "course.v1"])
    def test_invalid_scope_namespace_is_error(self, scope):
        doc = make_document(
            categories=[category("cat")],
            permissions=[permission(cat="cat", scopes=(scope,))],
        )

        messages = [i.message for i in _errors(SchemaValidator().validate([doc]))]

        assert any("invalid scope namespace" in m for m in messages)

    def test_hyphenated_scope_is_allowed(self):
        """Scope namespaces keep their registered spelling, e.g. ``course-v1``."""
        doc = make_document(
            categories=[category("cat")],
            permissions=[permission(cat="cat", scopes=("course-v1",))],
        )

        assert not _errors(SchemaValidator().validate([doc]))

    def test_role_without_scopes_is_error(self):
        doc = make_document(roles=[role(scopes=())])

        messages = [i.message for i in _errors(SchemaValidator().validate([doc]))]

        assert any("at least one scope" in m for m in messages)


class TestRequiredFields:
    """The subset of required fields the validator enforces today.

    Fuller required-field coverage (display fields, unknown keys, sizes) arrives
    with JSON Schema validation; these pin the rules already in place.
    """

    def test_empty_category_id_is_error(self):
        doc = make_document(categories=[category("")])

        messages = [i.message for i in _errors(SchemaValidator().validate([doc]))]

        assert any("Missing required field: category id" in m for m in messages)

    def test_permission_without_a_category_is_error(self):
        doc = make_document(permissions=[permission(cat="")])

        messages = [i.message for i in _errors(SchemaValidator().validate([doc]))]

        assert any("Missing required field: category for courses.view_course" in m for m in messages)


class TestExtensionReferences:
    """ADR 0023 §3: an extension must target a real role and real permissions."""

    def test_added_permission_must_exist(self):
        doc = make_document(
            categories=[category("cat")],
            permissions=[permission(cat="cat")],
            roles=[role()],
            role_extensions=[extension("course_editor", add_permissions=("courses.ghost",))],
        )

        messages = [i.message for i in _errors(SchemaValidator().validate([doc]))]

        assert any("references unknown permission 'courses.ghost'" in m for m in messages)

    def test_removed_permission_must_exist(self):
        doc = make_document(
            categories=[category("cat")],
            permissions=[permission(cat="cat")],
            roles=[role()],
            role_extensions=[extension("course_editor", remove_permissions=("courses.ghost",))],
        )

        messages = [i.message for i in _errors(SchemaValidator().validate([doc]))]

        assert any("references unknown permission 'courses.ghost'" in m for m in messages)

    def test_extension_may_target_a_role_from_another_document(self):
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


class TestHasErrors:
    """The gate the pipeline uses to decide whether to stop."""

    def test_true_when_any_issue_is_an_error(self):
        issues = [ValidationIssue(WARNING, "heads up"), ValidationIssue(ERROR, "boom")]

        assert SchemaValidator.has_errors(issues) is True

    def test_false_for_warnings_only(self):
        assert SchemaValidator.has_errors([ValidationIssue(WARNING, "heads up")]) is False

    def test_false_for_no_issues(self):
        assert SchemaValidator.has_errors([]) is False

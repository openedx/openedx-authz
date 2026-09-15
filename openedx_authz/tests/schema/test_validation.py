"""Unit tests for the schema validation step."""

from openedx_authz.engine.schema.validation import SchemaValidator

from .factories import category, extension, make_document, permission, role


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

"""Small builders and a stub discovery for schema pipeline tests."""

from __future__ import annotations

from openedx_authz.engine.schema.discovery import DiscoveredResource
from openedx_authz.engine.schema.types import (
    PermissionCategory,
    PermissionDefinition,
    RoleDefinition,
    RoleExtension,
    SchemaDocument,
    SourceRecord,
)


def make_source(name: str = "doc", schema_version: str = "1.0") -> SourceRecord:
    """Build a SourceRecord with predictable values for a named document."""
    return SourceRecord(
        distribution="test-dist",
        distribution_version="1.0",
        module=f"pkg.{name}",
        resource_path=f"{name}.authz.yaml",
        schema_version=schema_version,
        content_digest=f"digest-{name}",
    )


def make_document(
    name: str = "doc",
    *,
    priority: int = 100,
    schema_version: str = "1.0",
    categories=None,
    permissions=None,
    roles=None,
    role_extensions=None,
) -> SchemaDocument:
    """Build a SchemaDocument with sensible empty defaults."""
    return SchemaDocument(
        source=make_source(name, schema_version),
        priority=priority,
        categories=categories or [],
        permissions=permissions or [],
        roles=roles or [],
        role_extensions=role_extensions or [],
    )


def category(cid: str = "cat", **kwargs) -> PermissionCategory:
    return PermissionCategory(
        id=cid,
        display_name=kwargs.get("display_name", "Cat"),
        description=kwargs.get("description", "desc"),
        icon=kwargs.get("icon"),
    )


def permission(namespace="courses", name="view_course", *, cat="cat", scopes=("course-v1",), **kwargs):
    return PermissionDefinition(
        namespace=namespace,
        name=name,
        display_name=kwargs.get("display_name", "View"),
        description=kwargs.get("description", "desc"),
        category=cat,
        scopes=tuple(scopes),
        icon=kwargs.get("icon"),
    )


def role(rid="course_editor", *, scopes=("course-v1",), permissions=(), hidden=False, **kwargs):
    return RoleDefinition(
        id=rid,
        display_name=kwargs.get("display_name", "Editor"),
        description=kwargs.get("description", "desc"),
        scopes=tuple(scopes),
        permissions=tuple(permissions),
        icon=kwargs.get("icon"),
        hidden=hidden,
    )


def extension(role_id, **kwargs) -> RoleExtension:
    return RoleExtension(
        role=role_id,
        add_permissions=tuple(kwargs.get("add_permissions", ())),
        remove_permissions=tuple(kwargs.get("remove_permissions", ())),
        display_name=kwargs.get("display_name"),
        description=kwargs.get("description"),
        icon=kwargs.get("icon"),
        hidden=kwargs.get("hidden"),
    )


class StubDiscovery:
    """A discovery double whose ``resolve_contents`` returns preset bytes.

    Maps ``(package, resource_path)`` to raw bytes; ``discover`` returns the
    corresponding :class:`DiscoveredResource` list.
    """

    def __init__(self, contents: dict[tuple[str, str], bytes]):
        self._contents = contents

    def discover(self):
        return [
            DiscoveredResource(package=pkg, resource_path=path, origin="explicit")
            for (pkg, path) in self._contents
        ]

    def resolve_contents(self, resource: DiscoveredResource) -> bytes:
        return self._contents[(resource.package, resource.resource_path)]

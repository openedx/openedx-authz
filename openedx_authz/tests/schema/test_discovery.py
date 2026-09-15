"""Tests for directory-based schema discovery (ADR 0019)."""

import pytest

from openedx_authz.engine.schema.discovery import (
    SchemaDiscovery,
    SchemaDiscoveryError,
)

SCHEMA_DIR = "openedx_authz/authz/schema"
EXPECTED_FILES = {
    "course_permissions.yaml",
    "course_roles.yaml",
    "library_permissions.yaml",
    "library_roles.yaml",
}


def test_directory_is_expanded_to_yaml_files():
    resources = SchemaDiscovery(explicit_directories=[SCHEMA_DIR]).discover()
    names = {r.resource_path.rsplit("/", 1)[-1] for r in resources}
    assert names == EXPECTED_FILES


def test_discovered_resource_anchors_and_module_are_set():
    resources = SchemaDiscovery(explicit_directories=[SCHEMA_DIR]).discover()
    sample = resources[0]
    assert sample.package == "openedx_authz"  # importable anchor
    assert sample.resource_path.startswith("authz/schema/")
    assert sample.module == "openedx_authz.authz.schema"  # source identity


def test_contents_are_readable():
    discovery = SchemaDiscovery(explicit_directories=[SCHEMA_DIR])
    resources = discovery.discover()
    assert discovery.resolve_contents(resources[0])  # non-empty bytes


def test_discovery_is_deterministic():
    a = SchemaDiscovery(explicit_directories=[SCHEMA_DIR]).discover()
    b = SchemaDiscovery(explicit_directories=[SCHEMA_DIR]).discover()
    assert a == b


def test_unknown_directory_raises():
    with pytest.raises(SchemaDiscoveryError):
        SchemaDiscovery(explicit_directories=["openedx_authz/authz/does_not_exist"]).discover()


def test_own_entry_point_directory_is_discovered():
    # The installed 'authz.schema' entry point should yield this package's files.
    resources = SchemaDiscovery().discover()
    names = {r.resource_path.rsplit("/", 1)[-1] for r in resources}
    assert EXPECTED_FILES.issubset(names)


def test_duplicate_directories_are_deduplicated():
    resources = SchemaDiscovery(explicit_directories=[SCHEMA_DIR, SCHEMA_DIR]).discover()
    paths = [r.resource_path for r in resources]
    assert len(paths) == len(set(paths)) == len(EXPECTED_FILES)

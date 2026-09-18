"""Tests for directory-based schema discovery (ADR 0019)."""

import sys
from unittest import mock

import pytest

from openedx_authz.engine.schema.discovery import (
    DiscoveredResource,
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


class TestSettingsDirectories:
    """The operator/Tutor contribution route (ADR 0019 §1, ADR 0023 §4).

    Tutor patches ``OPENEDX_AUTHZ_SCHEMA_DIRECTORIES`` and then runs the
    deployment command, so this is the only path a site operator has for
    contributing a schema without shipping a Python package.
    """

    def test_settings_directories_are_discovered(self, settings):
        settings.OPENEDX_AUTHZ_SCHEMA_DIRECTORIES = [SCHEMA_DIR]

        resources = SchemaDiscovery().discover()

        names = {r.resource_path.rsplit("/", 1)[-1] for r in resources}
        assert EXPECTED_FILES.issubset(names)

    def test_absent_setting_contributes_nothing(self):
        """The default state: no deployment has declared the setting at all.

        ``OPENEDX_AUTHZ_SCHEMA_DIRECTORIES`` is deliberately not defined in the
        packaged settings, so it is read with a ``getattr`` default.
        """
        # pylint: disable=protected-access
        assert not SchemaDiscovery()._discover_settings_directories()

    def test_empty_setting_contributes_nothing(self, settings):
        settings.OPENEDX_AUTHZ_SCHEMA_DIRECTORIES = []

        # pylint: disable=protected-access
        assert not SchemaDiscovery()._discover_settings_directories()

    def test_none_setting_contributes_nothing(self, settings):
        settings.OPENEDX_AUTHZ_SCHEMA_DIRECTORIES = None

        # pylint: disable=protected-access
        assert not SchemaDiscovery()._discover_settings_directories()

    def test_bad_settings_directory_raises(self, settings):
        settings.OPENEDX_AUTHZ_SCHEMA_DIRECTORIES = ["openedx_authz/authz/does_not_exist"]

        with pytest.raises(SchemaDiscoveryError):
            SchemaDiscovery().discover()

    def test_settings_resource_is_marked_with_its_origin(self, settings):
        """``origin`` is diagnostic only, but it must identify the real route."""
        settings.OPENEDX_AUTHZ_SCHEMA_DIRECTORIES = [SCHEMA_DIR]

        # pylint: disable=protected-access
        resources = SchemaDiscovery()._discover_settings_directories()

        assert {r.origin for r in resources} == {"settings"}

    def test_missing_django_contributes_nothing(self):
        """The Casbin-free steps must stay importable and runnable without Django."""
        with mock.patch.dict(sys.modules, {"django.conf": None}):
            # pylint: disable=protected-access
            assert not SchemaDiscovery()._discover_settings_directories()

    def test_unconfigured_django_contributes_nothing(self, monkeypatch):
        """The pipeline must stay usable outside a Django process.

        Reading a setting with no ``DJANGO_SETTINGS_MODULE`` raises
        ``ImproperlyConfigured``, which would otherwise surface as an unrelated
        Django failure during a CI schema check.
        """
        # pylint: disable=import-outside-toplevel
        from django.conf import LazySettings
        from django.core.exceptions import ImproperlyConfigured

        def _unconfigured(_self, name):
            raise ImproperlyConfigured(f"Requested setting {name}, but settings are not configured")

        monkeypatch.setattr(LazySettings, "__getattr__", _unconfigured)

        # pylint: disable=protected-access
        assert not SchemaDiscovery()._discover_settings_directories()


class TestDiscoverySourcePrecedence:
    """Discovery merges sources in a fixed order and de-duplicates first-wins."""

    def test_entry_point_origin_wins_over_explicit_duplicate(self):
        """The same file from two routes is kept once, tagged with the first route."""
        resources = SchemaDiscovery(explicit_directories=[SCHEMA_DIR]).discover()

        assert {r.origin for r in resources} == {"entry_point"}
        assert len(resources) == len(EXPECTED_FILES)

    def test_explicit_only_directory_is_marked_explicit(self):
        resources = SchemaDiscovery(explicit_directories=[SCHEMA_DIR])._iter_directory(  # pylint: disable=protected-access
            SCHEMA_DIR, origin="explicit"
        )

        assert {r.origin for r in resources} == {"explicit"}


class TestDiscoveryErrors:
    """Every failure surfaces as SchemaDiscoveryError naming what went wrong."""

    def test_failing_provider_names_the_entry_point(self, monkeypatch):
        """ADR 0019 §1: discovery stops and reports which application failed.

        Continuing would apply an incomplete set of static definitions.
        """
        from importlib import metadata  # pylint: disable=import-outside-toplevel

        class _BrokenEntryPoint:
            """An ``authz.schema`` entry point whose import fails."""

            name = "broken_app"
            value = "broken_app.authz:get_schema_resources"

            @staticmethod
            def load():
                """Fail the way a broken module import would."""
                raise RuntimeError("provider exploded")

        monkeypatch.setattr(metadata, "entry_points", lambda **_kwargs: [_BrokenEntryPoint()])

        with pytest.raises(SchemaDiscoveryError) as exc_info:
            SchemaDiscovery().discover()

        assert "broken_app" in str(exc_info.value)
        assert "provider exploded" in str(exc_info.value)

    def test_provider_raising_when_called_is_also_reported(self, monkeypatch):
        from importlib import metadata  # pylint: disable=import-outside-toplevel

        class _BrokenProvider:
            """An entry point that imports fine but fails when called."""

            name = "late_app"
            value = "late_app.authz:get_schema_resources"

            @staticmethod
            def load():
                """Return a provider that raises on invocation."""

                def _provider():
                    raise ValueError("no schema here")

                return _provider

        monkeypatch.setattr(metadata, "entry_points", lambda **_kwargs: [_BrokenProvider()])

        with pytest.raises(SchemaDiscoveryError, match="late_app"):
            SchemaDiscovery().discover()

    def test_empty_directory_path_raises(self):
        with pytest.raises(SchemaDiscoveryError, match="Empty schema directory path"):
            SchemaDiscovery(explicit_directories=["/"]).discover()

    def test_unreadable_resource_raises(self):
        discovery = SchemaDiscovery(explicit_directories=[SCHEMA_DIR])
        resource = discovery.discover()[0]
        missing = DiscoveredResource(
            package=resource.package,
            resource_path="authz/schema/not_a_real_file.yaml",
            module=resource.module,
            origin="explicit",
        )

        with pytest.raises(SchemaDiscoveryError, match="Could not read schema resource"):
            discovery.resolve_contents(missing)


class TestSchemaFileSelection:
    """Only YAML *files* are picked up; other entries are ignored.

    These drive ``_iter_directory`` directly so the assertions cover just the
    directory being scanned, not the entry points ``discover`` also merges in.
    """

    @staticmethod
    def _iter(directory):
        # pylint: disable=protected-access
        return SchemaDiscovery()._iter_directory(directory, origin="explicit")

    def test_yml_suffix_is_accepted(self, tmp_path, monkeypatch):
        package = tmp_path / "fake_authz_pkg"
        (package / "schema").mkdir(parents=True)
        (package / "schema" / "roles.yml").write_text("schema_version: '1.0'\n", encoding="utf-8")
        (package / "schema" / "notes.txt").write_text("ignored\n", encoding="utf-8")
        monkeypatch.syspath_prepend(str(tmp_path))

        resources = self._iter("fake_authz_pkg/schema")

        assert [r.resource_path for r in resources] == ["schema/roles.yml"]

    def test_directory_named_like_a_schema_file_is_skipped(self, tmp_path, monkeypatch):
        package = tmp_path / "other_authz_pkg"
        # A directory named '*.yaml' passes the suffix check but is not a file.
        (package / "schema" / "subdir.yaml").mkdir(parents=True)
        (package / "schema" / "readme.md").write_text("ignored\n", encoding="utf-8")
        monkeypatch.syspath_prepend(str(tmp_path))

        assert not self._iter("other_authz_pkg/schema")

    def test_both_yaml_and_yml_are_collected_in_name_order(self, tmp_path, monkeypatch):
        package = tmp_path / "mixed_authz_pkg"
        (package / "schema").mkdir(parents=True)
        for name in ("b_roles.yml", "a_permissions.yaml"):
            (package / "schema" / name).write_text("schema_version: '1.0'\n", encoding="utf-8")
        monkeypatch.syspath_prepend(str(tmp_path))

        resources = self._iter("mixed_authz_pkg/schema")

        assert [r.resource_path for r in resources] == [
            "schema/a_permissions.yaml",
            "schema/b_roles.yml",
        ]

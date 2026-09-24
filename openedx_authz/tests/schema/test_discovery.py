"""Tests for directory-based schema discovery (ADR 0019).

The suite is grouped by the behaviour under test so each group documents one
contract of :class:`SchemaDiscovery`:

* ``TestDirectoryExpansion`` — a contributed directory expands to its YAML files.
* ``TestSettingsDirectories`` — the operator/Tutor settings contribution route.
* ``TestDiscoverySourcePrecedence`` — how sources merge and de-duplicate.
* ``TestDiscoveryErrors`` — every failure surfaces as ``SchemaDiscoveryError``.
* ``TestSchemaFileSelection`` — only YAML *files* are picked up.

"""

import pytest
from django.test import override_settings

from openedx_authz.engine.schema.discovery import (
    DiscoveredResource,
    Origin,
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


class TestDirectoryExpansion:
    """A contributed directory expands to the individual YAML files it holds."""

    def test_directory_is_expanded_to_yaml_files(self):
        """Passing a directory yields exactly its YAML files, by name."""
        resources = SchemaDiscovery(passed_in_directories=[SCHEMA_DIR]).discover()
        names = {r.resource_path.rsplit("/", 1)[-1] for r in resources}
        assert names == EXPECTED_FILES

    def test_discovered_resource_anchors_and_module_are_set(self):
        """Each resource records its import anchor, resource path, and module."""
        resources = SchemaDiscovery(passed_in_directories=[SCHEMA_DIR]).discover()
        sample = resources[0]
        assert sample.package == "openedx_authz"  # importable anchor
        assert sample.resource_path.startswith("authz/schema/")
        assert sample.module == "openedx_authz.authz.schema"  # source identity

    def test_contents_are_readable(self):
        """A discovered resource can be read back as non-empty bytes."""
        resources = SchemaDiscovery(passed_in_directories=[SCHEMA_DIR]).discover()
        assert resources[0].read_bytes()  # non-empty bytes

    def test_discovery_is_deterministic(self):
        """Repeated discovery over the same input returns an identical list."""
        a = SchemaDiscovery(passed_in_directories=[SCHEMA_DIR]).discover()
        b = SchemaDiscovery(passed_in_directories=[SCHEMA_DIR]).discover()
        assert a == b

    def test_unknown_directory_raises(self):
        """A directory that does not exist is a hard error, not a silent skip."""
        with pytest.raises(SchemaDiscoveryError):
            SchemaDiscovery(passed_in_directories=["openedx_authz/authz/does_not_exist"]).discover()

    def test_own_entry_point_directory_is_discovered(self):
        """The installed ``authz.schema`` entry point yields this package's files."""
        resources = SchemaDiscovery().discover()
        names = {r.resource_path.rsplit("/", 1)[-1] for r in resources}
        assert EXPECTED_FILES.issubset(names)

    def test_duplicate_directories_are_deduplicated(self):
        """The same directory passed twice yields each file only once."""
        resources = SchemaDiscovery(passed_in_directories=[SCHEMA_DIR, SCHEMA_DIR]).discover()
        paths = [r.resource_path for r in resources]
        assert len(paths) == len(set(paths)) == len(EXPECTED_FILES)


class TestSettingsDirectories:
    """The operator/Tutor contribution route (ADR 0019 §1, ADR 0023 §4).

    Tutor patches ``OPENEDX_AUTHZ_SCHEMA_DIRECTORIES`` and then runs the
    deployment command, so this is the only path a site operator has for
    contributing a schema without shipping a Python package.
    """

    @override_settings(OPENEDX_AUTHZ_SCHEMA_DIRECTORIES=["operator_authz_pkg/schema"])
    def test_settings_directories_are_discovered(self, tmp_path, monkeypatch):
        """A file reachable *only* via the setting is discovered and tagged.

        The directory points at a throwaway package that no entry point
        contributes, so the discovered file can only have come from the
        setting. Using this package's own ``SCHEMA_DIR`` here would pass even if
        the setting were ignored, because the installed entry point already
        yields those files (and first-wins de-dup would re-tag them).
        """
        package = tmp_path / "operator_authz_pkg"
        (package / "schema").mkdir(parents=True)
        (package / "schema" / "operator_roles.yaml").write_text("schema_version: '1.0'\n", encoding="utf-8")
        monkeypatch.syspath_prepend(str(tmp_path))

        resources = SchemaDiscovery().discover()

        [only] = [r for r in resources if r.origin == Origin.SETTINGS]
        assert only.resource_path == "schema/operator_roles.yaml"

    def test_absent_setting_contributes_nothing(self):
        """The default state: no deployment has declared the setting at all.

        ``OPENEDX_AUTHZ_SCHEMA_DIRECTORIES`` is deliberately not defined in the
        packaged settings, so it is read with a ``getattr`` default.
        """
        # pylint: disable=protected-access
        assert not SchemaDiscovery()._discover_settings_directories()

    @override_settings(OPENEDX_AUTHZ_SCHEMA_DIRECTORIES=[])
    def test_empty_setting_contributes_nothing(self):
        """An empty list is a no-op, not an error."""
        # pylint: disable=protected-access
        assert not SchemaDiscovery()._discover_settings_directories()

    @override_settings(OPENEDX_AUTHZ_SCHEMA_DIRECTORIES=None)
    def test_none_setting_contributes_nothing(self):
        """An explicit ``None`` degrades to no contribution."""
        # pylint: disable=protected-access
        assert not SchemaDiscovery()._discover_settings_directories()

    @override_settings(OPENEDX_AUTHZ_SCHEMA_DIRECTORIES=["openedx_authz/authz/does_not_exist"])
    def test_bad_settings_directory_raises(self):
        """A non-existent directory in the setting fails discovery loudly."""
        with pytest.raises(SchemaDiscoveryError):
            SchemaDiscovery().discover()

    @override_settings(OPENEDX_AUTHZ_SCHEMA_DIRECTORIES=[SCHEMA_DIR])
    def test_settings_resource_is_marked_with_its_origin(self):
        """``origin`` is diagnostic only, but it must identify the real route."""
        # pylint: disable=protected-access
        resources = SchemaDiscovery()._discover_settings_directories()

        assert {r.origin for r in resources} == {Origin.SETTINGS}

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

    def test_entry_point_origin_wins_over_passed_in_duplicate(self):
        """The same file from two routes is kept once, tagged with the first route."""
        resources = SchemaDiscovery(passed_in_directories=[SCHEMA_DIR]).discover()

        assert {r.origin for r in resources} == {Origin.ENTRY_POINT}
        assert len(resources) == len(EXPECTED_FILES)

    def test_passed_in_only_directory_is_marked_passed_in(self):
        """A directory reached only via the constructor keeps the passed-in origin."""
        resources = SchemaDiscovery(passed_in_directories=[SCHEMA_DIR])._iter_directory(  # pylint: disable=protected-access
            SCHEMA_DIR, origin=Origin.PASSED_IN
        )

        assert {r.origin for r in resources} == {Origin.PASSED_IN}


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
        """A provider that imports cleanly but raises on call is reported too."""
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

    def test_provider_returning_malformed_directory_raises(self, monkeypatch):
        """A provider that returns a bogus directory path fails discovery.

        Providers hand back directory strings; a malformed or non-existent path
        must surface as ``SchemaDiscoveryError`` naming the offending directory,
        not as an unrelated ``importlib.resources`` traceback.
        """
        from importlib import metadata  # pylint: disable=import-outside-toplevel

        class _MalformedProvider:
            """An entry point returning a directory that cannot be resolved."""

            name = "malformed_app"
            value = "malformed_app.authz:get_schema_resources"

            @staticmethod
            def load():
                """Return a provider yielding a non-existent directory path."""

                def _provider():
                    return ["no_such_top_level_pkg/authz/schema"]

                return _provider

        monkeypatch.setattr(metadata, "entry_points", lambda **_kwargs: [_MalformedProvider()])

        with pytest.raises(SchemaDiscoveryError, match="no_such_top_level_pkg/authz/schema"):
            SchemaDiscovery().discover()

    def test_empty_directory_path_raises(self):
        """A path that reduces to no segments is rejected explicitly."""
        with pytest.raises(SchemaDiscoveryError, match="Empty schema directory path"):
            SchemaDiscovery(passed_in_directories=["/"]).discover()

    def test_unreadable_resource_raises(self):
        """Reading a resource that no longer exists is a named error."""
        discovery = SchemaDiscovery(passed_in_directories=[SCHEMA_DIR])
        resource = discovery.discover()[0]
        missing = DiscoveredResource(
            package=resource.package,
            resource_path="authz/schema/not_a_real_file.yaml",
            module=resource.module,
            origin=Origin.PASSED_IN,
        )

        with pytest.raises(SchemaDiscoveryError, match="Could not read schema resource"):
            missing.read_bytes()


class TestSchemaFileSelection:
    """Only YAML *files* are picked up; other entries are ignored.

    These drive ``_iter_directory`` directly so the assertions cover just the
    directory being scanned, not the entry points ``discover`` also merges in.
    """

    @staticmethod
    def _iter(directory):
        # pylint: disable=protected-access
        return SchemaDiscovery()._iter_directory(directory, origin=Origin.PASSED_IN)

    def test_yml_suffix_is_accepted(self, tmp_path, monkeypatch):
        """A ``.yml`` file is collected and a ``.txt`` sibling is ignored."""
        package = tmp_path / "fake_authz_pkg"
        (package / "schema").mkdir(parents=True)
        (package / "schema" / "roles.yml").write_text("schema_version: '1.0'\n", encoding="utf-8")
        (package / "schema" / "notes.txt").write_text("ignored\n", encoding="utf-8")
        monkeypatch.syspath_prepend(str(tmp_path))

        resources = self._iter("fake_authz_pkg/schema")

        assert [r.resource_path for r in resources] == ["schema/roles.yml"]

    def test_directory_named_like_a_schema_file_is_skipped(self, tmp_path, monkeypatch):
        """A directory whose name ends in ``.yaml`` is not mistaken for a file."""
        package = tmp_path / "other_authz_pkg"
        # A directory named '*.yaml' passes the suffix check but is not a file.
        (package / "schema" / "subdir.yaml").mkdir(parents=True)
        (package / "schema" / "readme.md").write_text("ignored\n", encoding="utf-8")
        monkeypatch.syspath_prepend(str(tmp_path))

        assert not self._iter("other_authz_pkg/schema")

    def test_both_yaml_and_yml_are_collected_in_name_order(self, tmp_path, monkeypatch):
        """Mixed ``.yaml``/``.yml`` files come back sorted by name."""
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

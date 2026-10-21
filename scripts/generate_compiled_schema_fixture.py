#!/usr/bin/env python
"""Regenerate the compiled schema fixture used by the built-in applet tests.

Usage::

    make compiled_schema_fixture
"""

import json
import os

import django


def main():
    """Compile the built-in schema and write it to the fixture file."""
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "openedx_authz.settings.test")
    django.setup()

    # These modules read Django settings on import, so they load after setup.
    from openedx_authz.engine.schema.pipeline import SchemaPipeline
    from openedx_authz.tests.applets.test_builtin_definitions import COMPILED_SCHEMA_FIXTURE, schema_data

    data = schema_data(SchemaPipeline().compile())
    COMPILED_SCHEMA_FIXTURE.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()

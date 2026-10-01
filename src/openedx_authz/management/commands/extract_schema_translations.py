"""Django management command to extract translatable strings from the authz schema.

See openedx_authz.engine.schema.translation for why this exists and how it works.
"""

import os

from django.core.management.base import BaseCommand, CommandError

from openedx_authz import ROOT_DIRECTORY
from openedx_authz.engine.schema.translation import (
    SchemaTranslationExtractionError,
    extract_messages,
    render_module,
)

DEFAULT_OUTPUT_PATH = os.path.join(ROOT_DIRECTORY, "engine", "schema", "_generated_translations.py")


class Command(BaseCommand):
    """Generate a Python module with one pgettext() call per translatable schema string.

    Run this before ``i18n_tool extract`` (see the ``extract_translations`` Makefile
    target), so the generated calls are on disk for ``makemessages`` to scan.

    Example Usage:
        python manage.py extract_schema_translations
        python manage.py extract_schema_translations --output /path/to/file.py
    """

    help = "Extract translatable display_name/description strings from the authz schema into a generated module."

    def add_arguments(self, parser) -> None:
        """Add command-line arguments to the argument parser.

        Args:
            parser: The Django argument parser instance to configure.
        """
        parser.add_argument(
            "--output",
            type=str,
            default=DEFAULT_OUTPUT_PATH,
            help="Path to write the generated module to.",
        )

    def handle(self, *args, **options) -> None:
        """Extract schema translation messages and write the generated module."""
        try:
            messages = extract_messages()
        except SchemaTranslationExtractionError as exc:
            raise CommandError(str(exc)) from exc

        output_path = options["output"]
        with open(output_path, "w", encoding="utf-8") as output_file:
            output_file.write(render_module(messages))

        self.stdout.write(
            self.style.SUCCESS(f"Extracted {len(messages)} translatable schema string(s) to {output_path}")
        )

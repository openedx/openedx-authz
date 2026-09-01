0020: Translate Static Authorization Display Text Through OEP-58
################################################################

Status
******

**Draft**

Context
*******

The static authz schema contains the display names and descriptions used for roles, permissions, and permission categories. These strings belong to the contributing package, but users see them through APIs and frontend clients, so they need to follow the Open edX translation process.

Open edX already manages translations through OEP-58, with Atlas pulling translated catalogs from ``openedx-translations`` during image builds. Strings in configuration files need an additional extraction step because the normal tools cannot find them in Python or JavaScript source; ``tutor-contrib-aspects`` follows the same pattern for Superset assets.

Decision
********

1. Translate static fields through OEP-58
==========================================

Contributing packages write the source-language text in their schema. The extraction command then adds those fields to the OEP-58 input so they pass through ``openedx-translations`` and Atlas with the other Open edX strings.

2. Schema string extraction
===========================

The extraction command keeps enough context to distinguish each schema field. For example, a permission's display name and description remain separate translation messages even when they contain the same English text.

3. Store and return translated fields
=====================================

The API returns static display fields in the requested language and follows Django's normal fallback rules. Permission IDs, role IDs, and Paragon icon names keep the same value in every language because applications use them as identifiers.

4. User-defined role names
==========================

The static extraction command reads schema files from packages and therefore has no access to role names created later by administrators. Translation for those names belongs with the dynamic role model and API rather than the static OEP-58 process.

Consequences
************

* Static authorization display fields use the existing Open edX translation infrastructure.
* A translation build fails when it cannot extract a translatable schema field.
* Translation keys or message contexts must remain stable when files move between installation paths.
* Missing translations fall back through the existing Django language rules.
* User-defined role translation remains separate from static schema translation.

Rejected Alternatives
*********************

Put translated values directly in every schema file
===================================================

Each application would need to maintain its own locale structure inside the authorization format, separate from the Open edX translation pipeline.

References
**********

* `ADR 0017`_
* `Maintaining translations on an Open edX repository`_
* `Aspects translation extraction`_

.. _ADR 0017: 0017-static-authorization-schema.rst
.. _Maintaining translations on an Open edX repository: https://docs.openedx.org/en/latest/developers/how-tos/maintain-translations-in-your-repo.html
.. _Aspects translation extraction: https://github.com/openedx/tutor-contrib-aspects/blob/main/tutoraspects/translations/translate_utils.py

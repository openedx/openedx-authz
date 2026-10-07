0029: Tutor Implementation for Authorization Schema Discovery
##############################################################

Status
******

**Draft**

Context
*******

`ADR 0019`_ defines two ways to contribute a static authorization schema. An installed Python package registers an ``authz.schema`` entry point whose callable returns the package directories holding its YAML files. Alternatively, a deployment lists directories in the ``OPENEDX_AUTHZ_SCHEMA_DIRECTORIES`` Django setting; the directories listed must be anchored on an installed Python package.

Both `ADR 0019`_ §1 and `ADR 0023`_ §4 describe a third route for site operators: a Tutor plugin that uses an ``openedx-authz-schema`` patch:

.. code-block:: python

   from tutor import hooks

   hooks.Filters.ENV_PATCHES.add_item((
       "openedx-authz-schema",
       """
   schema_version: "1.0"
   priority: 200

   role_extensions:
     - role_id: course_editor
       add_permissions:
         - courses.export_course
   """,
   ))

1. How Tutor renders a patch
============================

Tutor's ``Renderer.patch()`` joins every plugin's contribution to a patch name into a single string and renders it to exactly one file. When two plugins contribute to ``openedx-authz-schema``, their contributions arrive concatenated.

2. Where a rendered file can land
=================================

Tutor mounts three directories into the LMS and CMS containers and their initialisation jobs: the two settings packages at ``lms/envs/tutor`` and ``cms/envs/tutor``, and ``/openedx/config``.

``/openedx/config`` is the directory Tutor already uses for rendered configuration, including ``lms.env.yml`` and ``cms.env.yml``.

Under Kubernetes these directories are ConfigMap mounts. Keys are derived from file basenames, so a subdirectory is flattened. A layout that relies on a subdirectory therefore behaves differently under ``k8s`` than under ``local`` and ``dev``.

Decision
********

1. Discover schema files by filesystem path
============================================

We will add an ``OPENEDX_AUTHZ_SCHEMA_FILES`` Django setting: a list of absolute filesystem paths, each naming one schema file. Discovery will read each listed file directly.

This will require ``src/openedx_authz/engine/schema/discovery.py`` to read from absolute filesystem paths.

2. Read each schema resource as a YAML document stream
======================================================

We will treat every schema resource as a multi-document YAML stream rather than as exactly one document. Each ``---``-separated document is a complete, independent contribution carrying its own ``schema_version`` and ``priority``, exactly as a separate file would.

This keeps a deployment system free to concatenate contributions into one file without their definitions colliding, and preserves the priority arbitration in `ADR 0023`_ §3 when several plugins contribute to the same patch. Empty documents — from empty contributions, trailing separators, or duplicated ``---`` markers — parse as ``None`` via ``yaml.safe_load_all()`` and can be skipped silently.

This will require an update to ``src/openedx_authz/engine/schema/loading.py`` to operate on multi-document streams.

3. Ship the Tutor integration as a plugin
==========================================

We will implement the Tutor integration as a new plugin in `openedx-tutor-plugins`_. The plugin will:

* define the ``openedx-authz-schema`` patch and render its content to a single YAML file. The plugin is responsible for inserting ``---`` separators between contributions — patch authors contribute only their YAML block. The plugin can render the patch with: ``{{ patch('openedx-authz-schema', separator='\n---\n') }}``;
* append that file's path to ``OPENEDX_AUTHZ_SCHEMA_FILES`` through Tutor's Open edX settings patches; and
* ensure the rendered file is present in the LMS and CMS containers and in their initialisation jobs for ``local``, ``dev``, and ``k8s`` deployments.

Example rendered file with two plugin contributions:

.. code-block:: yaml

   schema_version: "1.0"
   priority: 200

   role_extensions:
     - role_id: course_editor
       add_permissions:
         - courses.export_course
       display_name: Course author
       description: Creates and exports course content.
   ---
   schema_version: "1.0"
   priority: 100

   role_extensions:
     - role_id: course_editor
       remove_permissions:
         - courses.manage_tags
       display_name: Course author
       description: Creates and exports course content.

Consequences
************

* Site operators can contribute an authorization schema through Tutor configuration alone, the route `ADR 0019`_ §1 and `ADR 0023`_ §4 describe.
* Contributions from several plugins are preserved with their individual priorities.
* ``openedx-authz`` gains a second discovery path format.

Rejected Alternatives
*********************

Anchor on the Tutor settings package
=====================================

Render the file into the mounted settings directory and list ``lms/envs/tutor`` or ``cms/envs/tutor`` in ``OPENEDX_AUTHZ_SCHEMA_DIRECTORIES``.

* Pros: needs no change to ``openedx-authz``.
* Cons: attributes an operator override to the distribution that ships ``lms``; places non-Python data in a Django settings package.

Point the setting at a filesystem directory
===========================================

Accept filesystem *directories* rather than files, and list ``/openedx/config`` or a subdirectory of it.

* Pros: matches the existing directory-shaped contract more closely.
* Cons: scanning ``/openedx/config`` reads ``lms.env.yml`` and ``cms.env.yml``, which are not authorization schemas and fail validation. A dedicated subdirectory is flattened under Kubernetes ConfigMap mounts, so it works under ``local`` and ``dev`` but not under ``k8s``.

References
**********

* `ADR 0019`_
* `ADR 0023`_
* `openedx-tutor-plugins`_

.. _ADR 0019: 0019-authorization-schema-discovery.rst
.. _ADR 0023: 0023-extend-static-roles.rst
.. _openedx-tutor-plugins: https://github.com/openedx/openedx-tutor-plugins

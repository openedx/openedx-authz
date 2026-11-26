.. _Authorization Schema Reference:

Authorization Schema Reference
##############################

The Open edX Authorization schema, or authz schema, is a YAML configuration format for static permissions, permission categories, roles, and changes to existing roles. Applications ship schema files with their code, while site operators can contribute the same format through their deployment configuration. Deployment validates and compiles all contributions into the policy used by ``openedx-authz``.

Use this reference when creating or reviewing an authz schema file. The examples omit fields only when the surrounding section does not need them.

.. contents:: Contents
   :depth: 2
   :local:

.. toctree::
   :hidden:

   authorization-schema-json

Machine-readable schema
***********************

Each schema version has a downloadable authz JSON Schema that describes its fields, types, required values, and identifier formats:

* :download:`authz-schema-v1.json <../../src/openedx_authz/engine/schema/authz-schema-v1.json>` for schema version ``1.0`` (`view source <https://github.com/openedx/openedx-authz/blob/main/src/openedx_authz/engine/schema/authz-schema-v1.json>`__).
* :download:`authz-schema-v1.1.json <../../src/openedx_authz/engine/schema/authz-schema-v1.1.json>` for schema version ``1.1`` (`view source <https://github.com/openedx/openedx-authz/blob/main/src/openedx_authz/engine/schema/authz-schema-v1.1.json>`__). It accepts everything ``1.0`` accepts and adds the optional ``depends_on`` field to permissions.

You can also :doc:`browse the generated schema <authorization-schema-json>`. Editors and validation tools can use these files to check YAML files because JSON Schema applies to the data represented by both JSON and YAML.

The JSON Schema checks the structure of one file. The compiler also checks references across the combined schema, registered scope namespaces, available Paragon icons, and conflicts between contributions.

Complete example
****************

The following file defines one category, two permissions, one role, and an extension to a role defined elsewhere:

.. code-block:: yaml

   schema_version: "1.0"
   priority: 100

   permission_categories:
     - id: course_content
       display_name: Course content
       description: Permissions for viewing and editing course content.
       icon: Article

   permissions:
     - namespace: courses
       name: view_course
       display_name: View course
       description: View course configuration and content.
       category_id: course_content
       scopes:
         - course-v1
       icon: Visibility

     - namespace: courses
       name: view_course_updates
       display_name: View course updates
       description: View course update posts.
       category_id: course_content
       scopes:
         - course-v1
       icon: Visibility

   roles:
     - id: course_observer
       display_name: Course observer
       description: Reviews a course without changing it.
       scopes:
         - course-v1
       permissions:
         - courses.view_course
         - courses.view_course_updates

   role_extensions:
     - role_id: course_editor
       add_permissions:
         - courses.export_course

Top-level fields
****************

``schema_version``
==================

The version of the YAML format used by the file. Write it as a quoted ``major.minor`` value, such as ``"1.0"``. A deployment stops before changing the database when it encounters a version it cannot read.

The supported versions are ``"1.0"`` and ``"1.1"``. Each file is validated against the JSON Schema of the version it declares, so a deployment can load files of both versions together, and a file can move to ``1.1`` without the other files moving with it. A file needs ``"1.1"`` only to declare ``depends_on``, and a ``1.1`` file without it means the same as it would in ``1.0``. A ``1.0`` file that declares it fails validation with an unknown-field error.

``priority``
============

An integer used only when several files extend the same role through ``role_extensions`` and change the same field or permission. A higher number takes precedence. Contributions with the same priority may be combined when they agree or affect different fields, but conflicting values at the same priority fail validation.

Priority applies to role extensions only. It does not resolve conflicting base definitions: two files that declare the same permission category, permission, or role ID with different content are rejected regardless of their priorities. Priority also does not control the order shown in a user interface. Clients may sort roles, permissions, and categories for their own presentation.

``permission_categories``
=========================

A list of category definitions used to group permissions for display and discovery. Categories do not grant access.

``permissions``
===============

A list of permission definitions. Application checks use the stable permission ID formed from each permission's ``namespace`` and ``name``.

``roles``
=========

A list of static role definitions. A role lists every permission assigned to it.

``role_extensions``
===================

A list of changes to static roles defined in this file or another schema contribution. An extension changes only the fields it includes and does not copy or replace the complete role.

Permission categories
*********************

A category contains these fields:

``id``
   The stable category identifier. It is required and uses lowercase snake case, such as ``course_content`` or ``library_management``. Category IDs are global and do not include a permission namespace. Applications that use the same ID contribute permissions to the same category.

``display_name``
   The source-language name shown to users. It uses sentence case and is translated through the authz schema translation process.

``description``
   A complete source-language sentence describing the group of permissions.

``icon``
   An optional icon name exported by ``@openedx/paragon/icons``. The value is case-sensitive, such as ``Article``.

``hidden``
   An optional boolean that defaults to ``false``. A hidden category does not appear in normal discovery and selection interfaces, and neither do the permissions it contains. Hiding does not delete the category or its permissions, remove them from roles, or change permission checks. Role extensions cannot change this field.

For example:

.. code-block:: yaml

   permission_categories:
     - id: library_management
       display_name: Library management
       description: Permissions for managing content libraries.
       icon: Article

Permissions
***********

A permission contains these fields:

``namespace``
   The stable product domain that owns the permission. It uses lowercase snake case, such as ``courses`` or ``content_libraries``. The namespace does not need to match the Python package, Django app, IDA, or Tutor plugin that contributes the file. Code may move between applications without changing the permission ID.

``name``
   The operation within the product domain. It uses lowercase snake case and normally begins with a verb, such as ``view_course``, ``export_course``, or ``manage_library_tags``.

``display_name``
   The source-language name shown to users. Changing it does not change the permission ID used by application checks.

``description``
   A complete source-language sentence describing the access controlled by the permission.

``category_id``
   The complete ID of a category defined in the combined schema.

``scopes``
   The scope namespaces where the permission can apply. These values come from registered ``ScopeData`` types, such as ``course-v1``, ``ccx-v1``, or ``lib``.

``icon``
   An optional, case-sensitive icon name exported by ``@openedx/paragon/icons``.

``hidden``
   An optional boolean that defaults to ``false``. A hidden permission does not appear in normal discovery and selection interfaces or in role details. Hiding does not delete the permission, remove it from roles, or change permission checks. Role extensions cannot change this field.

``depends_on``
   An optional list of the complete IDs of the permissions this permission directly requires. Only the file that defines a permission declares its dependencies, and role extensions cannot add or remove them. Requires schema version ``1.1``. See :doc:`ADR 0034 <../decisions/0034-permission-dependencies-in-authorization-schema>`.

The complete permission ID joins ``namespace`` and ``name`` with a period. For example:

.. code-block:: yaml

   permissions:
     - namespace: content_libraries
       name: manage_library_tags
       display_name: Manage library tags
       description: Add, edit, and remove tags in a content library.
       category_id: library_management
       scopes:
         - lib

The complete ID is ``content_libraries.manage_library_tags``. Role definitions, role extensions, application checks, and API responses use this value.

The Casbin form ``act^content_libraries.manage_library_tags`` is an internal value and is not valid in a schema file.

Permission dependencies
=======================

A permission declares the permissions it directly requires in ``depends_on``. For example, editing library content requires viewing the library:

.. code-block:: yaml

   schema_version: "1.1"
   priority: 100

   permissions:
     - namespace: content_libraries
       name: edit_library_content
       display_name: Edit library content
       description: Create, edit, and delete content in a content library.
       category_id: library_content
       scopes:
         - lib
       depends_on:
         - content_libraries.view_library

Validation rejects a schema when:

* a dependency is not a permission defined in the combined schema;
* a permission depends on itself, or permissions depend on each other in a cycle;
* a dependency does not support every scope of the permission that depends on it;
* a visible permission depends on a hidden permission, or on a permission in a hidden category; or
* a role, after role extensions are applied, grants a permission without all of its direct and indirect dependencies.

The last rule applies to roles and role extensions in every file, whatever ``schema_version`` the file declares. If a ``1.1`` file adds ``depends_on`` to a permission, every role that grants that permission must also list its dependencies.

Only the file that defines a permission declares its dependencies. Another file that defines the same permission must declare the same ``depends_on``, which requires schema version ``1.1``. A ``1.0`` copy of a permission that declares dependencies is a conflicting definition.

Each direct dependency is stored as a Casbin ``g2`` row, such as ``g2, act^content_libraries.edit_library_content, act^content_libraries.view_library``. Loading the schema adds, keeps and removes these rows the same way as the ``p`` rows of role grants: an existing ``g2`` row that matches a dependency is kept as is, and a ``g2`` row that no schema declares is left in place. A permission check that a role passes for a permission also passes for the permissions it depends on, so a role stored only in the database still works when it lacks a dependency.

Roles
*****

A role contains these fields:

``id``
   The stable role identifier. It uses lowercase snake case, such as ``course_admin``, ``course_editor``, or ``library_author``. Role IDs do not include a product namespace because authorization uses the role within its supported scopes. The ``custom_`` prefix is reserved for roles that administrators create, so a schema role ID cannot start with it and validation reports the file that declares it.

``display_name``
   The source-language name shown to users.

``description``
   A complete source-language sentence describing what the role can do.

``scopes``
   The scope namespaces where the role can be assigned. Every permission listed by the role must support those scopes.

``permissions``
   A list of complete permission IDs. The role lists every permission it needs, including every direct and indirect dependency of those permissions (see `Permission dependencies`_).

``icon``
   An optional, case-sensitive icon name exported by ``@openedx/paragon/icons``.

``hidden``
   An optional boolean that defaults to ``false``. A hidden role does not appear in normal role discovery and selection interfaces. Hiding does not delete the role, remove existing assignments, or change permission checks.

For example:

.. code-block:: yaml

   roles:
     - id: library_reviewer
       display_name: Library reviewer
       description: Reviews library content without publishing it.
       scopes:
         - lib
       permissions:
         - content_libraries.view_library
         - content_libraries.view_library_team
       icon: Visibility

The Casbin form ``role^library_reviewer`` is an internal value and is not valid as ``roles.id`` or in a ``role_extensions.role_id`` reference.

Role extensions
***************

A role extension contains ``role_id`` and at least one field to change:

``role_id``
   The complete ID of an existing static role.

``add_permissions``
   Complete permission IDs to add to the role.

``remove_permissions``
   Complete permission IDs to remove from the role.

``display_name``, ``description``, and ``icon``
   Display metadata to replace. Metadata fields left out of the extension keep their current values.

``hidden``
   Whether the role appears in normal role discovery and selection interfaces.

For example, a deployment can allow course editors to export courses, remove their access to tag management, change the displayed role name, and hide the course auditor role:

.. code-block:: yaml

   schema_version: "1.0"
   priority: 200

   role_extensions:
     - role_id: course_editor
       add_permissions:
         - courses.export_course
       remove_permissions:
         - courses.manage_tags
       display_name: Course author
       description: Creates and exports course content.

     - role_id: course_auditor
       hidden: true

An extension fails validation when its target role or a referenced permission does not exist. It also fails when the resulting role grants a permission without its dependencies: an extension that adds a permission must also add the dependencies the role lacks, and ``remove_permissions`` cannot remove a dependency that another permission on the role still needs. Adding a permission already assigned to the role or removing one the role does not have produces a warning and leaves the result unchanged.

Identifier rules
****************

Permission namespaces, permission names, category IDs, and role IDs use lowercase letters, numbers, and underscores, begin with a letter, and match ``[a-z][a-z0-9_]*``. The period in a complete permission ID separates its namespace from its name and does not appear inside either part.

Valid identifiers include:

.. code-block:: text

   courses
   view_course
   courses.view_course
   course_content
   course_editor

The following values are invalid:

.. code-block:: text

   Courses.view_course       # uppercase letter
   courses:view_course       # wrong separator
   act^courses.view_course   # internal Casbin namespace
   course content            # space
   role^course_editor        # internal Casbin namespace
   custom_course_editor      # role ID prefix reserved for custom roles

Scope namespaces follow the spelling registered by their ``ScopeData`` type and may contain a hyphen. Do not apply the snake-case identifier rule to values such as ``course-v1`` or ``ccx-v1``.

Schema files in applications
****************************

Applications can keep schema resources under an ``authz/schema`` package directory. Filenames are chosen by the application, but separating permission and role definitions makes the resources easier to maintain:

.. code-block:: text

   course_authoring/
   └── authz/
       └── schema/
           ├── permissions.yaml
           └── roles.yaml

The application exposes the ``authz/schema`` directory through the ``openedx-authz`` schema entry point described in :doc:`ADR 0019 <../decisions/0019-authorization-schema-discovery>`. The directory path is relative to the Python module, which keeps discovery independent of virtual-environment and container paths. The compiler loads every ``.yaml`` file in that directory.

Tutor configuration for site operators
**************************************

A site operator can provide an authz schema through a Python Tutor plugin that uses the ``openedx-authz-schema`` patch. Run ``tutor plugins printroot`` to find the local plugin directory, then create ``openedx_authz_overrides.py`` there:

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
       remove_permissions:
         - courses.manage_tags
       display_name: Course author
       description: Creates and exports course content.

     - role_id: course_auditor
       hidden: true
       """,
   ))

Enable the plugin and save the rendered Tutor configuration:

.. code-block:: console

   tutor plugins enable openedx_authz_overrides
   tutor config save

The next deployment validates and compiles the patch with the schema files provided by applications.

Checking the resulting permissions
**********************************

After deployment, use the existing ``enforcement`` management command to check the policy stored in the database:

.. code-block:: console

   tutor local run lms ./manage.py lms enforcement

The command expects a subject, complete permission ID, and scope. Assuming ``alice`` has ``course_editor`` in ``course-v1:OpenedX+DemoX+DemoCourse``, the extension above produces these results:

.. code-block:: text

   alice courses.export_course course-v1:OpenedX+DemoX+DemoCourse
   ✓ ALLOWED: alice courses.export_course course-v1:OpenedX+DemoX+DemoCourse

   alice courses.manage_tags course-v1:OpenedX+DemoX+DemoCourse
   ✗ DENIED: alice courses.manage_tags course-v1:OpenedX+DemoX+DemoCourse

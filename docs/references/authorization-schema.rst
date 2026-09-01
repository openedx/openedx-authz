.. _Authorization Schema Reference:

Authorization Schema Reference
##############################

The Open edX Authorization schema, or authz schema, is a YAML configuration format for static permissions, permission categories, roles, and changes to existing roles. Applications ship schema files with their code, while site operators can contribute the same format through their deployment configuration. Deployment validates and compiles all contributions into the policy used by ``openedx-authz``.

Use this reference when creating or reviewing an authz schema file. The examples omit fields only when the surrounding section does not need them.

.. contents:: Contents
   :depth: 2
   :local:

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
       category: course_content
       scopes:
         - course-v1
       icon: Visibility

     - namespace: courses
       name: view_course_updates
       display_name: View course updates
       description: View course update posts.
       category: course_content
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
     - role: course_editor
       add_permissions:
         - courses.export_course

Top-level fields
****************

``schema_version``
==================

The version of the YAML format used by the file. Write it as a quoted ``major.minor`` value, such as ``"1.0"``. A deployment stops before changing the database when it encounters a version it cannot read.

``priority``
============

An integer used when several files change the same definition or role field. A higher number takes precedence. Contributions with the same priority may be combined when they agree or affect different fields, but conflicting values at the same priority fail validation.

Priority does not control the order shown in a user interface. Clients may sort roles, permissions, and categories for their own presentation.

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

``category``
   The complete ID of a category defined in the combined schema.

``scopes``
   The scope namespaces where the permission can apply. These values come from registered ``ScopeData`` types, such as ``course-v1``, ``ccx-v1``, or ``lib``.

``icon``
   An optional, case-sensitive icon name exported by ``@openedx/paragon/icons``.

The complete permission ID joins ``namespace`` and ``name`` with a period. For example:

.. code-block:: yaml

   permissions:
     - namespace: content_libraries
       name: manage_library_tags
       display_name: Manage library tags
       description: Add, edit, and remove tags in a content library.
       category: library_management
       scopes:
         - lib

The complete ID is ``content_libraries.manage_library_tags``. Role definitions, role extensions, application checks, and API responses use this value.

The Casbin form ``act^content_libraries.manage_library_tags`` is an internal value and is not valid in a schema file.

Roles
*****

A role contains these fields:

``id``
   The stable role identifier. It uses lowercase snake case, such as ``course_admin``, ``course_editor``, or ``library_author``. Role IDs do not include a product namespace because authorization uses the role within its supported scopes.

``display_name``
   The source-language name shown to users.

``description``
   A complete source-language sentence describing what the role can do.

``scopes``
   The scope namespaces where the role can be assigned. Every permission listed by the role must support those scopes.

``permissions``
   A list of complete permission IDs. The compiler does not infer one permission from another, so the role lists every permission it needs.

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

The Casbin form ``role^library_reviewer`` is an internal value and is not valid as ``roles.id`` or in a ``role_extensions.role`` reference.

Role extensions
***************

A role extension contains ``role`` and at least one field to change:

``role``
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
     - role: course_editor
       add_permissions:
         - courses.export_course
       remove_permissions:
         - courses.manage_tags
       display_name: Course author
       description: Creates and exports course content.

     - role: course_auditor
       hidden: true

An extension fails validation when its target role or a referenced permission does not exist. Adding a permission already assigned to the role or removing one the role does not have produces a warning and leaves the result unchanged.

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

Scope namespaces follow the spelling registered by their ``ScopeData`` type and may contain a hyphen. Do not apply the snake-case identifier rule to values such as ``course-v1`` or ``ccx-v1``.

Schema files in applications
****************************

Applications keep schema resources under an ``authz`` package directory and use the ``.authz.yaml`` suffix. The filename describes the definitions in the file using lowercase snake case:

.. code-block:: text

   course_authoring/
   └── authz/
       ├── course_permissions.authz.yaml
       └── course_roles.authz.yaml

The application exposes these package resources through the ``openedx-authz`` schema entry point. Resource paths are relative to the Python module, which keeps discovery independent of virtual-environment and container paths.

Tutor configuration for site operators
**************************************

A site operator can provide an authz schema through the ``openedx-authz-schema`` patch. Run ``tutor plugins printroot`` to find the local plugin directory, then create ``openedx-authz-overrides.yml`` there:

.. code-block:: yaml

   name: openedx-authz-overrides
   version: 0.1.0

   patches:
     openedx-authz-schema: |
       schema_version: "1.0"
       priority: 200

       role_extensions:
         - role: course_editor
           add_permissions:
             - courses.export_course
           remove_permissions:
             - courses.manage_tags
           display_name: Course author
           description: Creates and exports course content.

         - role: course_auditor
           hidden: true

Enable the plugin and save the rendered Tutor configuration:

.. code-block:: console

   tutor plugins enable openedx-authz-overrides
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

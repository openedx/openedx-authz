0023: Extend Static Roles Without Replacing Their Definitions
#############################################################

Status
******

**Draft**

Context
*******

Applications (Django applications, IDAs, etc.) define static roles in the authz schema, but operators may need to adapt those roles for a deployment. For example, a deployment may allow course editors to export courses, remove their access to tag management, change the text shown to users, or hide the course auditor role when that role does not apply to the site.

Copying the complete role definition would make the deployment responsible for every field and permission in the original role. It would also make application updates harder to adopt because the copied definition could drift from the role shipped by the application. `ADR 0017`_ therefore introduced ``role_extensions``, and this ADR explains how to use them in more detail.

Decision
********

1. Role extension fields
========================

A ``role_extensions`` entry identifies an existing static role with ``role`` and changes only the fields included in the entry. The :ref:`Authorization Schema Reference` describes these fields and includes complete examples for applications and Tutor configuration. An entry may use:

* ``add_permissions`` to add complete permission IDs;
* ``remove_permissions`` to remove complete permission IDs;
* ``display_name``, ``description``, and ``icon`` to replace display metadata; and
* ``hidden`` to control whether the role appears in normal role discovery and selection interfaces.

For example:

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

Fields that are not present keep their current value. An extension cannot change the role ID or replace its complete definition.

2. Hiding a role
================

Setting ``hidden: true`` removes the role from the normal API results used to discover roles and create assignments. It does not delete the role, remove existing assignments, or change permission checks, so its ID remains reserved and cannot be used for a dynamic role. This keeps hiding separate from removing a role, whose assignment checks are defined in `ADR 0018`_.

3. Validation and priority
==========================

The compiler resolves extensions after it loads every static role and permission. It rejects an extension when the target role or one of the permissions does not exist. Adding a permission that the role already has or removing one it does not have produces a warning and leaves the result unchanged.

Several applications or deployment files may extend the same role. Changes to different fields are combined, while priority resolves changes to the same metadata field or permission. If two contributions with the same priority disagree, validation stops before the database changes.

4. Tutor patch
==============

The Tutor integration for ``openedx-authz`` provides a named ``openedx-authz-schema`` patch. A Tutor operator can create a small Python plugin that uses this patch to contribute the same YAML accepted from application packages.

First, the operator runs ``tutor plugins printroot`` to find the local plugin directory and creates ``openedx_authz_overrides.py`` there:

.. code-block:: python

   from tutor import hooks

   hooks.Filters.ENV_PATCHES.add_item((
       "openedx-authz-schema",
       """
   schema_version: "1.0"
   priority: 200

   role_extensions:
     - role: course_editor
       add_permissions:
         - courses.export_course
       remove_permissions:
         - courses.manage_tags
       display_name: Course author
       description: Creates and exports course content for this site.
     - role: course_auditor
       hidden: true
       """,
   ))

The operator then enables the plugin and saves the Tutor configuration:

.. code-block:: console

   tutor plugins enable openedx_authz_overrides
   tutor config save

The next deployment passes the patch content to the compiler defined in `ADR 0019`_. After compilation, ``course_editor`` includes ``courses.export_course``, no longer includes ``courses.manage_tags``, and appears as "Course author." The ``course_auditor`` role remains valid for existing assignments but no longer appears in normal role discovery.

After deployment, the operator can check the resulting policy with the existing ``enforcement`` management command. Assuming ``alice`` has ``course_editor`` for ``course-v1:OpenedX+DemoX+DemoCourse``, the operator runs:

.. code-block:: console

   tutor local run lms ./manage.py lms enforcement

The interactive prompt can then check both sides of the extension:

.. code-block:: text

   alice courses.export_course course-v1:OpenedX+DemoX+DemoCourse
   ✓ ALLOWED: alice courses.export_course course-v1:OpenedX+DemoX+DemoCourse

   alice courses.manage_tags course-v1:OpenedX+DemoX+DemoCourse
   ✗ DENIED: alice courses.manage_tags course-v1:OpenedX+DemoX+DemoCourse

The patch changes how Tutor supplies the schema; it does not introduce a second schema format. Deployments that do not use Tutor provide the same YAML through a package entry point, file, or directory accepted by the compiler.

Consequences
************

* Applications can add to existing static roles without copying them.
* Operators can remove permissions or change role metadata through deployment configuration.
* Hiding a role does not revoke access from users who already have it.
* Priority resolves conflicts without a separate ``override`` field.
* Tutor and non-Tutor deployments use the same authz schema.
* The Tutor integration must define and document the ``openedx-authz-schema`` patch.

References
**********

* `ADR 0017`_
* `ADR 0018`_
* `ADR 0019`_
* :ref:`Authorization Schema Reference`
* `Tutor plugin development`_

.. _ADR 0017: 0017-static-authorization-schema.rst
.. _ADR 0018: 0018-authorization-schema-lifecycle.rst
.. _ADR 0019: 0019-authorization-schema-discovery.rst
.. _Tutor plugin development: https://docs.tutor.edly.io/plugins/v0/gettingstarted.html

0038: Hide Permission Categories and Permissions
################################################

Status
******

**Draft**

Context
*******

`ADR 0023`_ lets a role be hidden with the ``hidden`` flag, so that it does not appear in normal discovery and selection interfaces while keeping its assignments and permission checks. Permission categories and permissions have no equivalent.

The need comes from how the role catalog is used. `ADR 0028`_ defines the catalog as the source that clients read to discover roles, permissions and categories, and the Custom Roles feature builds its permission picker from it. Every permission in the schema is therefore offered by default, whether or not it is meant to be chosen by a person.

A permission can be valid and enforced without being something an administrator should see or select. Some examples:

* **Compatibility.** The ``course_legacy`` category holds the ``legacy_*`` permissions that map the legacy course roles into the authorization system. They must keep working for existing roles and assignments, but they are an implementation detail of the migration.
* **Internal or system actions.** Permissions that are checked by the platform or by other services, and that are granted only through predefined roles, have no meaning as a choice in a custom role.
* **Deprecated permissions.** A permission that is being phased out can stay in place for the roles that already grant it while it stops being offered for new use.
* **Permissions not ready for use.** A permission added together with a feature that is still in development, behind a flag, or not yet exposed in the UI can be defined in the schema without being offered yet.
* **Permissions defined by plugins or deployments.** An extension can define permissions that only make sense to its own roles and should not appear in the general selection lists.

In these cases, showing the permission has the same problems:

* Administrators see permissions with no clear meaning in the product, and may add them to custom roles that then depend on internals.
* Every role that grants them lists them in its details, which adds noise and hides the permissions that matter.
* The permissions are shared by several roles, so they cannot be hidden by hiding a role, and hiding a role would also hide grants that should stay visible.

The permissions cannot simply be removed. Existing roles and assignments may depend on them, and deleting them would change permission checks for users who have access today. The schema needs a way to keep a permission fully functional while keeping it out of discovery and selection.

Roles already have this mechanism, so the gap is one of consistency. Without it, the only way to hide permissions is to special-case them in each client, which would spread the same rule across the UI and API consumers instead of keeping it in the schema, where `ADR 0017`_ and `ADR 0031`_ place the source of truth for definitions.

Decision
********

1. Syntax
=========

Permission categories and permissions accept an optional ``hidden`` boolean in their base definitions. It defaults to ``false``.

.. code-block:: yaml

   permission_categories:
     - id: course_legacy
       display_name: Legacy compatibility
       # ...
       hidden: true

   permissions:
     - namespace: courses
       name: legacy_staff_role_permissions
       # ...
       hidden: true

The field is available in schema version ``1.0``. It is optional, so existing files keep their meaning.

2. Effect
=========

A permission is hidden when it sets ``hidden: true`` or when its category does. Hidden permissions are left out of:

* the ``permissions`` list of the role catalog (`ADR 0028`_);
* the ``permissions`` list of each role in the role catalog; and
* the ``categories`` list of the role catalog, which contains only non-hidden categories that still have a visible permission.

Hiding is a presentation rule only. It does not delete the definition, remove the permission from any role, remove role grants, or change permission checks. A role whose permissions are all hidden is still listed, with an empty ``permissions`` list. The Casbin policy rendered from the schema is the same with or without ``hidden``.

3. Role extensions
==================

Role extensions cannot change ``hidden`` on a category or a permission. They only change roles, so the flag is set only in the file that defines the category or permission, in line with the base definition rules of `ADR 0031`_.

4. Persistence
==============

The flag is stored with the schema models, so it is part of the schema snapshot, the source tracking described in `ADR 0025`_, and the compiled schema reference.

Consequences
************

* The permissions of a hidden category can be hidden with one flag.
* Permissions that must keep working but should not be offered, such as compatibility, internal or deprecated ones, can be kept for existing roles without appearing in the UI.
* An administrator cannot see, and therefore cannot select, hidden permissions in a custom role, but roles that already grant them continue to work.
* API clients that need hidden permissions cannot discover them through the role catalog.
* The schema models need a migration to store the flag.

Rejected Alternatives
*********************

Hide permissions through the role extension
===========================================

Permissions are shared by every role, so a per-role flag would hide the same permission inconsistently. It would also require the override rules that `ADR 0031`_ avoids for base definitions.

Delete permissions that should not be offered
=============================================

Existing roles and assignments may depend on them, and removing them would change permission checks. This is the case for compatibility permissions, and also for internal permissions that the platform enforces.

Hide only categories
====================

Individual permissions, such as internal actions in a visible category, could not be hidden.

References
**********

* `ADR 0017`_
* `ADR 0023`_
* `ADR 0025`_
* `ADR 0028`_
* `ADR 0031`_

.. _ADR 0017: 0017-static-authorization-schema.rst
.. _ADR 0023: 0023-extend-static-roles.rst
.. _ADR 0025: 0025-authorization-schema-source-tracking.rst
.. _ADR 0028: 0028-api-contract-for-role-catalog.rst
.. _ADR 0031: 0031-priority-applies-to-role-extensions-only.rst

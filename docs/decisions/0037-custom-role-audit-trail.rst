0037: Audit Trail for Custom Role Changes
#########################################

Status
******

**Draft**

Context
*******

`ADR 0035`_ and `ADR 0036`_ let Django staff and superusers create, edit, and remove custom roles,
and move a role's members to another role. Each change takes effect right away for every user who
holds the role.

`ADR 0012`_ records role assignment changes in ``RoleAssignmentAudit``, through the assignment events
in openedx-events. Nothing records changes to a role definition. An assignment deleted or moved
because a role was removed or reassigned is recorded the same way as a manual change, so the audit
cannot tell why it happened.

`ADR 0025`_ records which module contributed each static definition. It leaves source tracking for
dynamically created definitions to a future decision. This ADR is that decision for custom roles.

Decision
********

1. Record custom role changes in a dedicated table
==================================================

Every custom role change writes one record to a new ``RoleDefinitionAudit`` table, one per request:

.. list-table::
   :header-rows: 1

   * - Action
     - Operation
   * - Create, including a copy
     - ``created``
   * - Edit the name, description, or permissions
     - ``updated``
   * - Remove
     - ``deleted``
   * - Move members to another role
     - ``members_reassigned``
   * - A deployment drops grants for removed permissions (`ADR 0035`_)
     - ``updated``

Each record stores the operation, a ``change_id`` (UUID), the namespaced role key, the change, the
``actor_id``, and a timestamp. It follows the rules of `ADR 0012`_: values are plain strings with no
foreign keys, so records survive the removal of the role, and the actor comes from
``django_crum.get_current_user()``. The actor is ``None`` for system changes such as deployments.

Copies are recorded as ``created``. The server does not know a role was copied (`ADR 0036`_).

2. Store what changed
=====================

The ``changes`` field is JSON:

* ``created`` and ``deleted``: the full role: ``display_name``, ``description``, ``scope_types``,
  and ``permissions``. A ``deleted`` record also stores how the assignments were handled
  (``revoke`` or ``reassign``) and the ``target_role``, if any.
* ``updated``: only the fields that changed. A name or description change stores the old and new
  values. A permission change stores ``permissions_added`` and ``permissions_removed``.
* ``members_reassigned``: the ``target_role``.

3. Link assignment changes to the role change
=============================================

``RoleAssignmentAudit`` and the assignment event data gain a nullable ``role_change_id``. Every
assignment that is deleted or created because a role was removed or its members were moved carries
the ``change_id`` of that role change. Direct assignments and removals leave it empty.

The API generates the ``change_id`` before any write and passes it to the role event and to each
assignment event. The link does not depend on the order in which the handlers run.

4. Events
=========

openedx-events gains ``ROLE_DEFINITION_CREATED``, ``ROLE_DEFINITION_UPDATED``,
``ROLE_DEFINITION_DELETED``, and ``ROLE_MEMBERS_REASSIGNED``. The payload carries the operation,
``change_id``, role, ``changes`` (as a JSON string, so the event bus can serialize it), and
``actor_id``.

As in `ADR 0012`_, the events are sent with ``transaction.on_commit``, a handler writes the audit
record, and the same setting that disables the assignment audit handler disables this one.

5. Provenance of custom roles
=============================

Custom roles have no source links in the `ADR 0025`_ tables (`ADR 0035`_). Their ``created`` record
says who created them and when. No other source tracking is added for custom roles.

6. Reading the history
======================

The table is registered in Django admin and can be filtered by role, operation, actor, and
timestamp. A REST endpoint for the history is deferred until a UI needs it.

Consequences
************

* One migration adds ``RoleDefinitionAudit`` and the ``role_change_id`` field on
  ``RoleAssignmentAudit``.
* openedx-events needs a release with the new events and the ``role_change_id`` field before this
  ships. Adding a field to the assignment event data is backward-compatible (`ADR 0012`_).
* The assignments affected by removing a role or moving its members can be found by filtering
  ``RoleAssignmentAudit`` by ``role_change_id``.
* The audit is best-effort, as in `ADR 0012`_. If the write fails, the role change still applies.
* Changes to static roles are not recorded here. Deployments and `ADR 0025`_ source tracking cover
  them.
* The history is visible in Django admin only. No UI or REST API is added.

Rejected Alternatives
*********************

Reuse ``RoleAssignmentAudit``
=============================

Definition changes have no subject or scope, and an edit can change many permissions at once.
Mixing both kinds of record in one table would leave columns empty and make the admin filters
ambiguous.

``django-simple-history`` on the definition tables
==================================================

A permission edit touches many grant rows, so one request would produce many snapshots with no
single record of the change. Bulk writes also bypass model signals, the same problem `ADR 0012`_
found for ``ExtendedCasbinRule``.

Source rows in the `ADR 0025`_ tables
=====================================

Those tables record which module contributed a definition, and they hold the current state. A user
is not a module, and an audit needs every change, not only the latest one.

References
**********

* `ADR 0012`_
* `ADR 0025`_
* `ADR 0035`_
* `ADR 0036`_

.. _ADR 0012: 0012-auditability.rst
.. _ADR 0025: 0025-authorization-schema-source-tracking.rst
.. _ADR 0035: 0035-custom-role-persistence.rst
.. _ADR 0036: 0036-api-contract-for-custom-roles.rst

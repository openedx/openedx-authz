0012: Auditability for Authorization Changes
############################################

Status
******

**Draft**

Context
*******

The existing architecture (see `ADR 0005`_) introduced ``ExtendedCasbinRule``, which adds
``created_at``, ``updated_at``, and a ``metadata`` JSON field to the ``CasbinRule`` table.
This is not an audit trail: there is no actor, no operation type, and no mechanism for
downstream consumers to react to changes.

As the framework is adopted across more Open edX services, operators and developers need
answers the current system cannot provide:

- Who assigned this role, and when?
- Who removed a user's access, and was it intentional?
- Why was a permission check denied?

A spike (OEPM-Spike: RBAC AuthZ Auditability) examined how peer systems approach this.
Auditability decomposes into three dimensions:

1. **Attribution**: who changed access? (role assignments, removals)
2. **Explainability**: why was access granted or denied? (policy evaluation at check time)
3. **Usage**: who used access? (resource access events, business operations)

SpiceDB and OpenFGA version the entire authorization graph, enabling historical
reconstruction. Keycloak uses event listeners on administrative actions. openedx-authz sits
between these: a mutable policy store with no built-in audit layer.

The pycasbin ecosystem has no audit plugin and no mechanism in the
``casbin-django-orm-adapter`` for change tracking. ``WatcherEx`` provides rule-level hooks
but carries no actor context and does not cover update operations.

Two transitive dependencies already cover what is needed:

- **django-crum** (``0.7.9``, via ``edx-django-utils``): ``get_current_user()`` from
  thread-local. Returns ``None`` in non-request contexts, treated as a system actor.
- **django-simple-history** (``3.11.0``, via ``edx-organizations``): model-level change
  tracking with actor, timestamp, and before/after state. Not applied to any openedx-authz
  model yet.

The Auth0 FGA Logging API (October 2025) defines three acceptance criteria for this feature:

- Who made a permission change? (attribution)
- What did a user access or attempt? (explainability + usage)
- Can logs be exported to external systems? (SIEM, Aspects)

Decision
********

Three independent mechanisms, each answering a different question:

- ``OpenedxPublicSignal``: something happened, react now
- ``RoleAssignmentAudit``: what happened, in what order, performed by whom
- ``django-simple-history`` on ``ExtendedCasbinRule``: what was the full state at time T
  (future work)

Attribution: Role Lifecycle Events and Audit Table
==================================================

Emit an ``OpenedxPublicSignal`` from ``openedx_authz.api.roles`` after every successful role
assignment or removal, via ``transaction.on_commit``. A Celery handler writes the event to
``RoleAssignmentAudit``.

The handler is enabled by default. Operators with Aspects or a SIEM can disable it via a
Django setting to avoid the redundant write. If the handler fails, the Casbin write and the
event are unaffected.

.. note::

   Whether to write to the audit table in the same process (no Celery) or via a separate
   task is an open question. Needs latency benchmarking before implementation.

Event payload
-------------

.. code:: python

    {
        "operation": "ASSIGN" | "REMOVE",
        "user":      "<namespaced subject key, e.g. user^alice>",
        "role":      "<namespaced role key, e.g. role^instructor>",
        "scope":     "<namespaced scope key, e.g. course-v1^course-v1:Org+Course+Run>",
        "actor":     "<username of the caller, or None for system actor>",
        "timestamp": "<ISO 8601 UTC datetime>",
    }

The actor is resolved from ``django_crum.get_current_user()`` at API call time. No callers
need to pass ``actor=`` explicitly.

Audit table
-----------

``RoleAssignmentAudit`` mirrors the event payload. Registered in Django admin, filterable by
user, role, scope, actor, and timestamp.

Subject, role, and scope are stored as plain namespaced key strings (e.g. ``user^alice``,
``role^instructor``, ``lib^lib:Org1:lib1``). There are no FK references to live ``Subject``,
``Scope``, or Casbin tables. Audit records survive the deletion of the underlying objects by
design: the value of an audit log depends on its unconditional durability.

Because there are no FK references, the namespace prefix embedded in each string is the only
available signal for categorizing records by type. Admin filters (e.g. "content library",
"course") rely on ``scope__startswith`` lookups against that prefix rather than relational
joins.

Developer extensibility
-----------------------

Plugin authors register handlers on the ``OpenedxPublicSignal`` to react to role lifecycle
events (notifications, cache updates, analytics). Developers without an event bus can consume
the underlying Django signal directly. If an event bus is configured, events are forwarded to
Aspects or external systems automatically.

Explainability: Real-Time Decision Context
==========================================

Expose ``enforce_ex()`` through the public Python API. It returns ``(result, explain_rule)``:
the boolean decision and the matched policy rule. Callers get the exact rule that allowed or
denied the request.

Enforcement events are opt-in via ``AUTHZ_ENFORCEMENT_EVENTS_ENABLED``. When enabled, each
check fires an ``OpenedxPublicSignal`` forwarded to plugin consumers or an event bus. No audit
table is written: the volume makes per-check storage impractical.

Historical explainability ("why did this user have access last Tuesday?") is deferred. Two
options are available, both requiring a breaking change to ``is_user_allowed`` to accept
``as_of``:

- **Option A (event replay):** Replay ``ASSIGN``/``REMOVE`` events from ``RoleAssignmentAudit``
  up to T. No extra infrastructure; the data is already there once attribution is implemented.
- **Option B (snapshots):** Add ``HistoricalRecords()`` to ``ExtendedCasbinRule`` and use
  ``as_of(T)`` for the full rule state, including policy definitions. History collection must
  start before the target timestamp.

``authz.policy`` is loaded into the DB and covered by Option B. ``model.conf`` is not
persisted. A ``model_hash`` field on ``ExtendedCasbinRule`` would let historical queries
detect whether the model changed.

Consequences
************

Attribution
===========

- Operators get a filterable role assignment history in Django admin. No external tooling
  required.
- Developers get a stable ``OpenedxPublicSignal`` extension point. First formally defined
  event in openedx-authz.
- Events are best-effort: if the audit write fails, the Casbin policy is still durable.
  Consumers requiring guaranteed delivery must implement their own retry logic.
- ``actor`` is nullable. Non-request contexts (management commands, background tasks) record
  ``None``, logged as a system operation.
- No new dependencies introduced.
- Callers of ``openedx_authz.api.roles`` need no signature changes.

Explainability
==============

- Developers can retrieve the matched policy rule at check time for "why was this denied?"
  debugging.
- The explanation is point-in-time only. Historical explainability is deferred.
- Enforcement events are opt-in by design. Enabling them without an external consumer
  produces events that are emitted and discarded.
- No new dependencies introduced.

Both flows
==========

- ``RoleAssignmentAudit`` introduces a new migration. No existing table is modified.
- The ``OpenedxPublicSignal`` schema is a public API surface. Field additions are
  backward-compatible; removals and renames are breaking changes.
- Usage auditing belongs at the application layer (Open edX tracking events, Aspects), not
  in the authorization library.
- ``RoleAssignmentAudit`` is not tamper-proof. Compliance-grade immutability is a
  later-phase concern.
- Audit records are independent from live authorization state. Deleting a subject, scope, or
  role does not remove its audit history. Records may reference identifiers that no longer
  exist in the system.
- ``actor`` is the exception: it is stored as a FK to the ``User`` model with ``SET_NULL``.
  Deleting a user sets ``actor`` to ``None``, losing attribution for any audit records they
  produced. This is an accepted trade-off: user deletion is rare in Open edX (the standard
  path is retirement, which anonymizes rather than hard-deletes), and the FK enables direct
  admin filtering by actor. If unconditional attribution durability is needed, ``actor``
  should be changed to a plain string field.

Alternatives Considered
***********************

``django-simple-history`` on ``ExtendedCasbinRule`` as the attribution audit trail
===================================================================================

Rejected for three reasons:

- ``save_policy`` does bulk delete + bulk create and bypasses model signals. Any policy
  reload creates a new snapshot. The ``history_date`` reflects when the table was written,
  not when a role was assigned. Snapshot diffs cannot tell apart "Alice was assigned
  instructor" from "policy reloaded, Alice already had the role."
- Model signals are not fired for bulk operations, so writes through ``save_policy`` are not
  captured at all.
- ``ExtendedCasbinRule`` fields (``ptype``, ``v0``--``v5``) are semi-opaque and require an
  interpretation layer. ``RoleAssignmentAudit`` translates at write time.

``django-simple-history`` remains the right tool for Option B (point-in-time state
reconstruction), where it is a snapshot mechanism, not an operation log.

Use Cases Addressed
*******************

+------------------------------------------------------------+---------------+
| Description                                                | Flow          |
+============================================================+===============+
| Operator: who assigned a role to a user, and when?        | Attribution   |
+------------------------------------------------------------+---------------+
| Operator: who removed a role from a user, and when?       | Attribution   |
+------------------------------------------------------------+---------------+
| Operator: full role history for a given user              | Attribution   |
+------------------------------------------------------------+---------------+
| Operator: access control history for a given resource     | Attribution   |
+------------------------------------------------------------+---------------+
| Developer: hook into role lifecycle events from a plugin  | Attribution   |
+------------------------------------------------------------+---------------+
| Operator/Developer: query role assignment history via API | Attribution   |
+------------------------------------------------------------+---------------+
| Developer: understand why a permission check was denied   | Explainability|
+------------------------------------------------------------+---------------+
| Operator/Developer: inspect a user's current permissions  | Explainability|
+------------------------------------------------------------+---------------+

Deferred: resource access history / usage auditing; export to SIEM / Aspects (available as
a side effect of the event signal once an event bus is configured, not a first-class
deliverable of this ADR).

References
**********

- `ADR 0002`_
- `ADR 0004`_
- `ADR 0005`_
- `Auth0 FGA Logging API`_
- `openedx-events documentation`_
- `django-simple-history documentation`_
- `django-crum documentation`_
- OEPM-Spike: RBAC AuthZ Auditability

.. _ADR 0002: https://github.com/openedx/openedx-authz/blob/main/docs/decisions/0002-authorization-model-foundation.rst
.. _ADR 0004: https://github.com/openedx/openedx-authz/blob/main/docs/decisions/0004-technology-selection.rst
.. _ADR 0005: https://github.com/openedx/openedx-authz/blob/main/docs/decisions/0005-architecture-and-data-modeling.rst
.. _Auth0 FGA Logging API: https://auth0.com/blog/auth0-fga-logging-api-a-complete-audit-trail-for-authorization/
.. _openedx-events documentation: https://docs.openedx.org/projects/openedx-events/en/latest/
.. _django-simple-history documentation: https://django-simple-history.readthedocs.io/
.. _django-crum documentation: https://pypi.org/project/django-crum/

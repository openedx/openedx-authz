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

Operators and developers need answers the current system cannot provide:

- Who assigned this role, and when?
- Who removed a user's access, and was it intentional?
- Why was a permission check denied?

A spike (OEPM-Spike: RBAC AuthZ Auditability) examined how peer systems approach this.
Auditability decomposes into three dimensions:

1. **Attribution**: who changed access? (role assignments, removals)
2. **Explainability**: why was access granted or denied? (policy evaluation at check time)
3. **Usage**: who used access? (resource access events, business operations)

`SpiceDB`_ and `OpenFGA`_ track the full authorization graph as a versioned changelog,
enabling historical reconstruction. Keycloak uses event listeners on administrative actions.
openedx-authz sits between these: a mutable policy store with no built-in audit layer.
(See `OEPM-Spike\: RBAC AuthZ Auditability`_ for the peer system analysis.)

The pycasbin ecosystem has no audit plugin. Two transitive dependencies cover what is needed:
``django-crum`` (via ``edx-django-utils``) for actor capture, and ``django-simple-history``
(via ``edx-organizations``) for point-in-time state reconstruction.

Decision
********

Three independent mechanisms, each answering a different question:

- ``OpenedxPublicSignal``: something happened, react now
- ``RoleAssignmentAudit``: what happened, in what order, performed by whom
- ``django-simple-history`` on ``ExtendedCasbinRule``: what was the full state at time T
  (future work)

See the `OEPM-Spike\: RBAC AuthZ Auditability`_ for the architecture diagram of the three
flows.

#. Attribution: Role Lifecycle Events and Audit Table
=====================================================

Emit an ``OpenedxPublicSignal`` from ``openedx_authz.api.roles`` after every successful role
assignment or removal, via ``transaction.on_commit``. A synchronous Django signal receiver
writes the event to ``RoleAssignmentAudit`` in the same process.

The handler is enabled by default. Operators with Aspects or a SIEM can disable it via a
Django setting to avoid the redundant write. If the handler fails, the Casbin write and the
event are unaffected.

Event payload
-------------

.. code:: python

    {
        "operation": "created" | "deleted",
        "subject":   "<namespaced subject key, e.g. user^alice>",
        "role":      "<namespaced role key, e.g. role^instructor>",
        "scope":     "<namespaced scope key, e.g. course-v1^course-v1:Org+Course+Run>",
        "actor":     "<User object for the caller, or None for system actor>",
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

#. Explainability: Real-Time Decision Context
=============================================

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
  The `Auth0 FGA Logging API`_ uses this same pattern: their logging API is an event store
  that you replay to answer historical questions.
- **Option B (snapshots):** Add ``HistoricalRecords()`` to ``ExtendedCasbinRule`` and use
  ``as_of(T)`` for the full rule state, including policy definitions. History collection must
  start before the target timestamp.

``authz.policy`` is loaded into the DB and covered by Option B. ``model.conf`` is not
persisted. A ``model_hash`` field on ``ExtendedCasbinRule`` would let historical queries
detect whether the model changed.

Consequences
************

#. **Operators get a filterable role assignment history in Django admin.** No external
   tooling required.

#. **Developers get a stable** ``OpenedxPublicSignal`` **extension point.** First formally
   defined event in openedx-authz. Callers of ``openedx_authz.api.roles`` need no signature
   changes.

#. **Events are best-effort.** If the audit write fails, the Casbin policy is still durable.
   Consumers requiring guaranteed delivery must implement their own retry logic.

#. **``actor`` is nullable.** Non-request contexts (management commands, background tasks)
   record ``None``, logged as a system operation. ``actor`` is stored as a FK to ``User``
   with ``SET_NULL``: deleting a user loses attribution for their audit records. This is
   accepted because user deletion is rare in Open edX (retirement anonymizes rather than
   hard-deletes), and the FK enables admin filtering by actor. If unconditional attribution
   durability is needed, ``actor`` should be a plain string field instead.

#. **Audit records are independent from live authorization state.** Deleting a subject,
   scope, or role does not remove its audit history. Records may reference identifiers that
   no longer exist.

#. **``RoleAssignmentAudit`` introduces a new migration.** No existing table is modified.

#. **The** ``OpenedxPublicSignal`` **schema is a public API surface.** Field additions are
   backward-compatible; removals and renames are breaking changes.

#. **``RoleAssignmentAudit`` is not tamper-proof.** Compliance-grade immutability is a
   later-phase concern.

#. **No new dependencies introduced.** ``django-crum`` and ``django-simple-history`` are
   already transitive dependencies.

#. **Usage auditing belongs at the application layer** (Open edX tracking events, Aspects),
   not in the authorization library.

#. **Developers can retrieve the matched policy rule at check time** for "why was this
   denied?" debugging. The explanation is point-in-time only; historical explainability is
   deferred.

#. **Enforcement events are opt-in by design.** Enabling them without an external consumer
   produces events that are emitted and discarded.

Alternatives Considered
***********************

``django-simple-history`` on ``ExtendedCasbinRule`` as the attribution audit trail
===================================================================================

Rejected for three reasons:

- ``save_policy`` (`casbin-django-orm-adapter adapter.py`_) uses ``QuerySet.delete()`` and
  ``bulk_create``, both of which bypass model signals. History snapshots reflect when the
  table was written, not when a role was assigned.
- ``ExtendedCasbinRule`` fields (``ptype``, ``v0``--``v5``) are semi-opaque and require an
  interpretation layer. ``RoleAssignmentAudit`` translates at write time.

``django-simple-history`` remains the right tool for Option B (point-in-time state
reconstruction), where it is a snapshot mechanism, not an operation log.

References
**********

- `ADR 0002`_
- `ADR 0004`_
- `ADR 0005`_
- `Auth0 FGA Logging API`_
- `openedx-events documentation`_
- `django-simple-history documentation`_
- `django-crum documentation`_
- `OEPM-Spike: RBAC AuthZ Auditability`_

.. _ADR 0002: https://github.com/openedx/openedx-authz/blob/main/docs/decisions/0002-authorization-model-foundation.rst
.. _ADR 0004: https://github.com/openedx/openedx-authz/blob/main/docs/decisions/0004-technology-selection.rst
.. _ADR 0005: https://github.com/openedx/openedx-authz/blob/main/docs/decisions/0005-architecture-and-data-modeling.rst
.. _Auth0 FGA Logging API: https://auth0.com/blog/auth0-fga-logging-api-a-complete-audit-trail-for-authorization/
.. _SpiceDB: https://github.com/authzed/spicedb
.. _OpenFGA: https://openfga.dev/
.. _openedx-events documentation: https://docs.openedx.org/projects/openedx-events/en/latest/
.. _django-simple-history documentation: https://django-simple-history.readthedocs.io/
.. _django-crum documentation: https://pypi.org/project/django-crum/
.. _casbin-django-orm-adapter adapter.py: https://github.com/officialpycasbin/django-orm-adapter/blob/main/casbin_adapter/adapter.py
.. _OEPM-Spike\: RBAC AuthZ Auditability: https://openedx.atlassian.net/wiki/spaces/OEPM/pages/6045859842/Spike+-+RBAC+AuthZ+-+Auditability

0017: Package Layout Convention for REST API Views
###################################################

Status
******

**Draft**

Context
*******

``openedx_authz/rest_api/v1/`` started as a single ``views.py`` module holding every REST endpoint, reusable and consumer-specific alike. `ADR 0016`_ determined which endpoints expose authorization's own data (roles, permissions, assignments, scopes) and which don't, and applied that determination by moving endpoints into two new subpackages: ``admin_console/`` for the five endpoints shaped around the Admin Console's specific workflows, and ``course_authoring/`` for ``WaffleFlagStatesAPIView``, the one documented exception whose data belongs to Course Authoring.

Both moves happened as part of applying ADR 0016's ownership rule, but the packaging convention itself was never written down on its own. This ADR names that convention so a future endpoint has a clear placement rule to apply, instead of requiring a fresh architecture discussion each time one is added.

Decision
********

1. A reusable authorization endpoint, one that answers the same question identically for any caller, stays in ``rest_api/v1/views.py``.
2. An endpoint shaped around one specific consumer's workflow, whose data is still authorization's own, moves into a subpackage named after that consumer, for example ``admin_console/``. This is a package-placement decision. `ADR 0016`_ already governs which data counts as authorization's own; this rule only decides where an endpoint's code lives once that question is settled.
3. An endpoint that is a documented exception to domain ownership (`ADR 0016`_ decision item 4) moves into a subpackage named after the domain its data actually belongs to, for example ``course_authoring/``, rather than staying in ``views.py`` next to endpoints it doesn't behave like.
4. A subpackage owns its ``views.py``, plus its own ``filters.py`` or ``serializers.py`` for classes not shared with the generic module. Mixins and serializers used by both the generic module and a subpackage stay in ``rest_api/v1/serializers.py``.
5. Each subpackage's ``__init__.py`` states in one short docstring which of rule 2 or rule 3 justifies its existence, so a reader can tell why the package exists without reconstructing the reasoning from the ADRs.

Consequences
************

1. A new endpoint has an immediate placement rule. Reusable, authorization's own data stays in ``views.py``. Consumer-specific, authorization's own data gets a subpackage named after that consumer. Data belonging to a different domain gets a subpackage named after that domain.
2. ``admin_console/`` and ``course_authoring/`` are the first two instances of this pattern and can be pointed to directly as examples, instead of re-deriving the reasoning from `ADR 0016`_ for every new case.
3. This ADR does not add a new domain-ownership rule. Package boundaries follow from `ADR 0016`_'s ownership determination.

Rejected Alternatives
*********************

**Deciding placement ad hoc for each new endpoint, without naming the rule.**
This already happened once. The ``admin_console/`` and ``course_authoring/`` moves were correct applications of `ADR 0016`_, but the general rule behind them was never written down as its own decision. Leaving it unstated risks each future endpoint getting a different, undocumented rationale for where it lives.

**One subpackage per domain, regardless of consumer.**
Grouping every Admin-Console-shaped endpoint and every other consumer-specific endpoint into a single package by domain alone would still mix unrelated consumers together, the same problem the original ``views.py`` had. Naming a subpackage after the actual consumer keeps its audience unambiguous.

References
**********

* `ADR 0016`_
* `ADR 0015`_

.. _ADR 0016: 0016-rest-api-domain-ownership-boundary.rst
.. _ADR 0015: 0015-expose-course-authoring-waffle-flag-state-via-rest-api.rst

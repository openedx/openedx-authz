0018: Cross-Domain Filtering via Open edX Filters
###################################################

Status
******

**Proposed** *2026-07-31*

Context
*******

`ADR 0016`_ establishes that ``openedx_authz``'s reusable endpoints, ``PermissionValidationMeView``, ``RoleUserAPIView``, and ``RoleListView``, must answer "what can this subject do" identically regardless of caller, and must not depend on another domain's concept. `PR #361`_ violated that guarantee directly, hardcoding course-authoring-flag checks inside ``PermissionValidationMeView`` and its siblings, and was reverted for unvalidated correctness and performance risk (`ADR 0015`_).

The need the flag work was solving hasn't gone away. `frontend-app-admin-console PR #176`_'s own ADR documents that the paginated assignment endpoints (``AssignmentsAPIView``, ``TeamMemberAssignmentsAPIView``) currently rely entirely on Casbin staying in sync with the flag through `ADR 0013`_'s migration, since client-side filtering would break their pagination and counts. That migration is opt-in and off by default, so these endpoints can return stale, flag-disabled assignments today. The same ADR also names ``PermissionValidationMeView`` as its intended future authority: "once the release-blocking permission endpoints can safely enforce per-scope flag logic, the client-side filtering... can also be removed in favor of authoritative server-side enforcement." It explicitly does not distinguish "denied for lack of permission" from "hidden because a flag is off"; both resolve to the same boolean.

Open edX Filters (OEP-50) already exists for this class of problem. An ``OpenEdxPublicFilter`` subclass defines a domain-neutral extension point, and a separate ``PipelineStep`` implementation, registered only through ``OPEN_EDX_FILTERS_CONFIG``, supplies the actual behavior. Unconfigured, a filter's ``run_pipeline`` returns its input unchanged, a true no-op.

Reviewing the eight generic and Admin-Console-shaped endpoints in ``openedx_authz.rest_api`` against this mechanism split them into three groups:

* Endpoints whose response items each carry their own ``scope``: ``PermissionValidationMeView``, ``ScopesAPIView``, ``AssignmentsAPIView``, ``TeamMemberAssignmentsAPIView``. These can filter their response list directly.
* ``TeamMembersAPIView`` resolves per-user assignments (each with a ``scope``) before aggregating them into ``assignation_count``; filtering has to run on that pre-aggregation list, before the count is computed.
* ``RoleUserAPIView`` and ``RoleListView`` take exactly one scope per request, as a query parameter. There's nothing item-level to filter, the question is whether that one scope is visible at all.

``PermissionValidationMeView`` has an additional constraint the others don't. Every requested ``{action, scope}`` pair must get exactly one result back, so an item can never simply be dropped, only have its ``allowed`` flag flipped.

``AdminConsoleOrgsAPIView`` returns raw ``Organization`` rows rather than scope-shaped data, though an org-level scope concept exists (``OrgGlobData`` and its subclasses). Filtering it by course-authoring visibility alone would incorrectly hide an org's library content if the org has both. This ADR does not resolve that question.

Decision
********

* ``openedx_authz`` endpoints that need scope-based filtering call a single shared, domain-neutral filter, ``AuthorizationDataRequested`` (``openedx_authz/filters.py``), filter type ``org.openedx.authz.authorization_data.requested.v1``. Its name and type describe the data flowing through it, Authorization's own data, so it stays applicable to a future non-REST caller, or a use case other than course-authoring visibility, without renaming anything. Its signature is typed: ``run_filter(cls, items: list[ScopedItem], username: str) -> list[ScopedItem]``, where ``ScopedItem`` is a ``TypedDict`` requiring only ``scope``. ``username`` is available for a pipeline step that needs to make a per-user decision, the course-authoring step's staff bypass being the current example; the filter itself never inspects it. Every caller uses the returned list directly, as its own result; no endpoint inspects or reconciles what a pipeline step did to it.
* What happens to an item whose scope is hidden is entirely the configured pipeline step's decision, driven by the item's own shape, not by which endpoint sent it: an item with no ``scope`` (an any-scope check) is left untouched, an item with an ``allowed`` key is kept with ``allowed`` flipped to ``False``, any other item is dropped.
* ``PermissionValidationMeView``, ``AssignmentsAPIView``, and ``TeamMemberAssignmentsAPIView`` build their full response list manually before paginating it, so they call the filter directly on that list, before ``paginator.paginate_queryset()`` runs.
* ``ScopesAPIView`` is a ``generics.ListAPIView``, whose queryset DRF paginates automatically. Filtering has to happen in ``filter_queryset()``, before ``paginate_queryset()`` runs there too, materializing the queryset into a plain list first; filtering after pagination would make the page's ``count`` report the pre-filter total while ``results`` showed fewer items. Its rows are keyed by ``scope_id``/``org_name``/``scope_type``, not ``scope``, so each row is given a temporary ``scope`` key (computed the same way ``ScopeSerializer.get_external_key`` does) before calling the filter, then the key is removed again, since it isn't part of this endpoint's actual queryset shape.
* ``TeamMembersAPIView`` calls it on each user's resolved assignments, before ``assignation_count`` is computed.
* ``RoleUserAPIView`` and ``RoleListView`` materialize their single query-param scope as a one-item list and call the same filter. When it comes back empty, the endpoint returns its normal paginated 200 response with ``count: 0`` and an empty ``results``, the same shape it already returns for a visible scope with no roles or assignments yet. No error status, no message distinguishing "hidden by flag" from "nothing here."
* ``AdminConsoleOrgsAPIView`` is not wired into this mechanism by this ADR; its precision gap (course-glob visibility alone can't determine whether an org's other content is visible) is left open.
* The course-authoring-specific pipeline step, the only implementation of this filter that exists today, lives in ``openedx_authz/rest_api/v1/course_authoring/pipeline.py``, alongside ``WaffleFlagStatesAPIView`` (`ADR 0016`_, `ADR 0017`_). It is not registered by default; a Tutor plugin patches ``OPEN_EDX_FILTERS_CONFIG`` to enable it where needed.

Example, ``PermissionValidationMeView`` marks rather than drops:

.. code:: json

   // Request
   [{"action": "courses.view_course", "scope": "course-v1:Org1+HIDDEN101+2024"}]

   // Response, course-authoring pipeline step configured and the scope is flag-disabled
   [{"action": "courses.view_course", "scope": "course-v1:Org1+HIDDEN101+2024", "allowed": false}]

Example, ``AssignmentsAPIView`` drops the hidden item entirely:

.. code:: json

   // Before filtering
   {"count": 2, "results": [
       {"role": "course_staff", "scope": "course-v1:Org1+HIDDEN101+2024", "username": "jane"},
       {"role": "library_admin", "scope": "lib:Org1:LIB1", "username": "jane"}
   ]}

   // After filtering
   {"count": 1, "results": [
       {"role": "library_admin", "scope": "lib:Org1:LIB1", "username": "jane"}
   ]}

Example, ``RoleUserAPIView`` with a hidden scope, a normal empty 200:

.. code:: json

   // GET /api/authz/v1/roles/users/?scope=course-v1:Org1+HIDDEN101+2024
   {"count": 0, "next": null, "previous": null, "results": []}

Consequences
************

1. The reusable endpoints stay answerable identically regardless of caller in their own code, ``views.py`` never imports or depends on course-authoring concepts; the dependency lives entirely in the opt-in pipeline step.
2. ``AssignmentsAPIView`` and ``TeamMemberAssignmentsAPIView`` stop relying solely on Casbin migration staying in sync with the flag, closing the staleness gap `frontend-app-admin-console PR #176`_'s ADR names as a known limitation.
3. ``PermissionValidationMeView`` can become the authoritative source `frontend-app-admin-console PR #176`_'s own ADR says it's waiting for, letting that MFE eventually retire its client-side ``useCourseAuthoringFlag`` resolution.
4. Removing the flag later means deleting ``course_authoring/pipeline.py``'s contents and the Tutor plugin patch that registers it. No endpoint code changes.
5. ``openedx-filters`` becomes a new dependency of this repo.
6. Every endpoint calls the filter the same way and trusts its result directly; the mark-versus-drop distinction is entirely the pipeline step's concern, invisible to callers.
7. ``RoleUserAPIView`` and ``RoleListView`` build a one-item list purely to reuse the shared contract for what is conceptually a single boolean check, minor indirection for consistency's sake.
8. ``AdminConsoleOrgsAPIView``'s filtering remains unresolved; the Organization filter in the Admin Console keeps depending on the frontend's own ``isOrgAuthoringEnabled`` logic until this is addressed.
9. The pipeline step exists and is tested, but nothing registers it by default; a deployment sees no behavior change until its own settings add it to ``OPEN_EDX_FILTERS_CONFIG``.
10. ``PermissionValidationMeView``'s any-scope check (``scope`` omitted, checking across every scope the user is granted an action in) isn't filtered at all. An item's scope is ``None`` by the time it reaches the filter, with no candidate list attached, so there's nothing for a pipeline step to check visibility against. This is left open, not silently handled.

Rejected Alternatives
*********************

* **Hardcoding the flag check directly in the generic endpoints (PR #361's original approach)**: breaks the "same answer regardless of caller" guarantee `ADR 0016`_ establishes, and already carries an unvalidated correctness and performance risk on release-blocking paths.
* **Leaving filtering entirely to the calling application, the status quo**: works for the Admin Console's small, client-owned filter dropdowns, but not for the paginated assignment endpoints, where client-side filtering breaks pagination and counts, `frontend-app-admin-console PR #176`_'s own ADR names this as the reason those endpoints currently just tolerate staleness instead.
* **Implementing the course-authoring pipeline step in CMS or edx-platform instead of this repo**: the check needs the same guarded ``enable_authz_course_authoring``/``WaffleFlagOrgOverrideModel`` imports ``WaffleFlagStatesAPIView`` already uses; duplicating that pattern in a second repo is worse than colocating it with the one exception already established for this flag.
* **A separate filter type per endpoint instead of one shared contract**: every per-item-scoped endpoint needs the identical "list of scope-bearing items in, filtered list out" shape; per-endpoint filter types would fragment configuration for behavior that's actually the same.

References
**********

* `ADR 0015`_
* `ADR 0016`_
* `ADR 0017`_
* `ADR 0013`_
* `PR #361`_
* `frontend-app-admin-console PR #176`_

.. _ADR 0015: 0015-expose-course-authoring-waffle-flag-state-via-rest-api.rst
.. _ADR 0016: 0016-rest-api-domain-ownership-boundary.rst
.. _ADR 0017: 0017-rest-api-package-layout-convention.rst
.. _ADR 0013: 0013-course-authoring-automatic-migration.rst
.. _PR #361: https://github.com/openedx/openedx-authz/pull/361
.. _frontend-app-admin-console PR #176: https://github.com/openedx/frontend-app-admin-console/pull/176

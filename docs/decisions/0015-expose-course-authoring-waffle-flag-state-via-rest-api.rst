0015: Expose Course-Authoring Waffle Flag State via REST API
##############################################################

Status
******

**Accepted**

Context
*******

``authz.enable_course_authoring`` is a three-tier flag (`ADR 0010`_), where a course override wins over an org override, which in turn wins over the platform default.

`Issue #340`_ and `issue #341`_ report that the admin-console MFE keeps showing Authoring-related roles, scopes, and role assignments even when this flag is off, since nothing currently checks it. Both issues ask for a simpler rule than the full cascade. The Authoring UI should show if the flag is on at any level (platform, org, or course), and hide only if it's off at every level. `A review comment on frontend-app-admin-console#176`_ lays out the fuller course/org/platform truth table this problem could ideally follow.

`PR #361`_ attempted to enforce that full truth table directly inside ``PermissionValidationMeView`` and other REST API endpoints, checking the flag per scope on every request. Per `PR #361's own comment thread`_, those endpoints are release-blocking for Verawood, so baking precise per-scope flag logic into them risked correctness and performance on critical paths without enough test coverage across the framework to be confident in time for the release. That approach was reverted, and the team pivoted to `issue #358`_ instead, exposing the flag's raw state through a dedicated endpoint and letting the admin-console MFE apply the simpler #340/#341 rule itself, deferring precise per-scope filtering to a later cycle.

Neither edx-toggles nor openedx-platform expose a suitable public API to consume the flag's state for this use case. ``openedx/core/djangoapps/waffle_utils/views.py``'s ``ToggleStateView``, built on edx-toggles' reporting machinery (`edx_toggles source`_) and wired at ``/api/toggles/v0/state/``, requires ``IsStaff`` and reports the state of every registered toggle at once. ``WaffleFlagOrgOverrideModel.override_value(name, key)`` and its course-level counterpart (`waffle_utils models source`_) each require already knowing which specific org or course to check.

Decision
********

1. Add ``GET /api/authz/v1/waffle-flag-states/``, backed by ``openedx_authz.utils.get_waffle_flag_states()``, returning the flag's global state plus every org and course that currently has an active override, split into 'on' and 'off' lists.
2. The admin-console MFE decides what to show using this response, applying the #340/#341 rule for this release.
3. This supersedes PR #361's approach of enforcing the full cascade inside REST API endpoints themselves, for this release. PR #361's per-scope logic (``is_scope_visible``/``has_visible_scope``) stays documented on that branch for a future cycle.
4. Making the REST API endpoints themselves aware of the flag is still an open problem, and needs to be addressed on its own. Given the release timeline and the risk PR #361 surfaced, the team chose this more straightforward solution for now.

Consequences
************

#. **Release-blocking endpoints stay untouched.** ``PermissionValidationMeView`` and the other endpoints named in PR #361 keep their existing behavior. This endpoint is additive, isolated, low-risk.
#. **One place answers "what's the flag's state right now."** ``get_waffle_flag_states()`` centralizes the lookup, reusing ``enable_authz_course_authoring()`` for the global tier and querying ``WaffleFlagOrgOverrideModel``/``WaffleFlagCourseOverrideModel`` directly for the org/course tiers, since no public API answers "which orgs/courses have an override."
#. **The MFE bears the filtering complexity.** Applying the #340/#341 "any tier on" rule, and any future precise per-course/per-org filtering, is MFE-side logic from here on.
#. **Callers must resolve their own scope against the raw override lists.** The response lists every org and course override on the instance rather than filtering to the caller's context. Determining whether course authoring is enabled for one course requires checking that course's ID in ``course_overrides``, then its org in ``org_overrides``, then falling back to ``global``, in that precedence order. ``frontend-app-admin-console``'s ``useCourseAuthoringFlag`` hook (`frontend-app-admin-console#176`_) implements that resolution and is the reference for any other consumer building the same logic.
#. **These override queries scan the whole table, unfiltered by any specific org/course.** For instances with many overrides, this is a full-table read on every call. Not a problem at current scale, but worth revisiting if usage grows (see `issue #360`_).
#. **The endpoint takes no client-supplied parameters.** ``get_waffle_flag_states()`` reads no query params or request body, so there's no request shape to validate or malform. Access is gated by ``IsAuthenticated`` (session or JWT); CSRF protection doesn't apply here since GET is a safe method Django's CSRF middleware doesn't check.
#. **``openedx_authz.utils`` now depends on** ``common.djangoapps.student.roles.enable_authz_course_authoring`` **and** ``openedx.core.djangoapps.waffle_utils.models``, guarded by the same standalone-import pattern already used elsewhere in this repo (``rest_api/utils.py``, ``handlers.py``). This is a temporary, direct openedx-platform dependency, tracked as follow-up work under `issue #360`_ (moving the dependency direction so services depend on ``openedx_authz``).
#. **The exception has a planned end.** `Issue #377`_ tracks removing ``WaffleFlagStatesAPIView`` and ``get_waffle_flag_states()`` when ``authz.enable_course_authoring`` is deprecated. The flag's ``toggle_target_removal_date`` is 2027-06-09, tracked upstream at `openedx-platform#37927`_.

Rejected Alternatives
**********************

**Enforcing the full per-scope truth table inside release-blocking REST API endpoints (PR #361)**
  Correctness and performance across the whole framework weren't validated in time for a release-blocking change, per PR #361's own comment thread. The simpler #340/#341 rule doesn't need per-scope precision to ship.

**Relying on** ``/api/toggles/v0/state/``
  openedx-platform already exposes a generic toggle-state endpoint, ``ToggleStateView`` in ``openedx/core/djangoapps/waffle_utils/views.py``, wired at this URL. Its ``permission_classes`` require ``IsStaff``, which the admin-console MFE's calling user is not guaranteed to be, and it reports the state of every registered toggle at once.

**Building a replacement endpoint outside openedx-authz now, and migrating the admin-console MFE to it.**
  Authorization owns endpoints that expose roles, permissions, assignments, or scopes; a course-authoring flag's raw state is none of those, so this endpoint sits outside authorization's domain. But knowing it doesn't belong here doesn't tell us where it does belong, and that question is out of scope for this ADR. Moving the endpoint now would require a new owner, a new endpoint, and a migration in the admin-console MFE. That work is not justified for a flag with a ``toggle_target_removal_date`` of 2027-06-09 (tracked upstream at `openedx-platform#37927`_; see `Issue #377`_). If the flag remains in use past that date, revisit this alternative.

Addendum (2026-07-28)
*********************

`ADR 0016`_ audited every endpoint in ``openedx_authz.rest_api`` against Open edX's domain vocabulary rather than by who calls it today. That vocabulary classifies authorization as a supporting subdomain (`ADR 0018 in openedx-events`_), the same tier as Analytics. Both are independent of any single application and are consumed across learning, content authoring, enterprise, and other areas. ADR 0016 also draws a line between two separate questions. Domain ownership asks whether the endpoint exposes authorization data, such as roles, permissions, assignments, or scopes. Package placement asks whether the endpoint is reusable, or tailored to one workflow. An Admin Console screen aggregating tasks from several domains doesn't make the Admin Console a domain in its own right; each task it aggregates still belongs to whichever domain already owns it.

``WaffleFlagStatesAPIView`` is the one endpoint in this repository that fails the domain-ownership question, since a course-authoring flag's state isn't authorization data. ADR 0016 turned that into a standing rule: authorization endpoints must not compute or expose another domain's data, and this endpoint is the sole, explicitly named exception to it. We keep it here as a temporary, documented exception for the reason given above, rather than build and migrate to an equivalent endpoint elsewhere. The exception applies only to ``WaffleFlagStatesAPIView`` and must not be extended to other endpoints.

Decision item 4 above called endpoint-level flag awareness an open problem to revisit later. ADR 0016 closes that question. Authorization endpoints cannot compute or expose another domain's data, so ``PermissionValidationMeView``, ``RoleUserAPIView``, and ``RoleListView`` must not depend on the course-authoring flag. This is a domain-boundary rule that holds regardless of release timeline, so revisiting it after this release won't change the answer. Any future flag-aware behavior for these endpoints would have to live in whichever domain ends up owning the flag.

References
**********

* `ADR 0010`_
* `ADR 0016`_
* `ADR 0018 in openedx-events`_
* `Issue #340`_
* `Issue #341`_
* `Issue #358`_
* `Issue #360`_
* `Issue #377`_
* `PR #361`_
* `PR #361's own comment thread`_
* `A review comment on frontend-app-admin-console#176`_
* `frontend-app-admin-console#176`_
* `openedx-platform#37927`_

.. _ADR 0010: 0010-course-authoring-flag.rst
.. _ADR 0016: 0016-rest-api-domain-ownership-boundary.rst
.. _ADR 0018 in openedx-events: https://github.com/openedx/openedx-events/blob/main/docs/decisions/0018-supporting-subdomain-modules.rst
.. _Issue #340: https://github.com/openedx/openedx-authz/issues/340
.. _issue #340: https://github.com/openedx/openedx-authz/issues/340
.. _Issue #341: https://github.com/openedx/openedx-authz/issues/341
.. _issue #341: https://github.com/openedx/openedx-authz/issues/341
.. _Issue #358: https://github.com/openedx/openedx-authz/issues/358
.. _issue #358: https://github.com/openedx/openedx-authz/issues/358
.. _Issue #360: https://github.com/openedx/openedx-authz/issues/360
.. _issue #360: https://github.com/openedx/openedx-authz/issues/360
.. _Issue #377: https://github.com/openedx/openedx-authz/issues/377
.. _PR #361: https://github.com/openedx/openedx-authz/pull/361
.. _PR #361's own comment thread: https://github.com/openedx/openedx-authz/pull/361#issuecomment-4967053225
.. _A review comment on frontend-app-admin-console#176: https://github.com/openedx/frontend-app-admin-console/pull/176#issuecomment-4900922914
.. _frontend-app-admin-console#176: https://github.com/openedx/frontend-app-admin-console/pull/176
.. _edx_toggles source: https://github.com/openedx/edx-toggles/blob/master/edx_toggles/toggles/state/internal/report.py
.. _waffle_utils models source: https://github.com/openedx/openedx-platform/blob/master/openedx/core/djangoapps/waffle_utils/models.py
.. _openedx-platform#37927: https://github.com/openedx/openedx-platform/issues/37927

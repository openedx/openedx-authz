0015: Expose Course-Authoring Waffle Flag State via REST API
##############################################################

Status
******

**Draft**

Context
*******

For the Verawood release, the Admin Console needs to hide course-authoring roles, scopes, and assignments when course authoring is disabled. This ADR records the temporary solution of giving the Admin Console the flag state so it can decide what to show.

``authz.enable_course_authoring`` is a three-tier flag (`ADR 0010`_), where a course override wins over an org override, which in turn wins over the platform default.

`Issue #340`_ and `issue #341`_ report that the admin-console MFE keeps showing Authoring-related roles, scopes, and role assignments even when this flag is off, since nothing currently checks it. Both issues ask for a simpler rule than the full cascade. The Authoring UI should show if the flag is on at any level (platform, org, or course), and hide only if it's off at every level. `A review comment on frontend-app-admin-console#176`_ lays out the fuller course/org/platform truth table this problem could ideally follow.

`PR #361`_ explored enforcing that full truth table inside ``PermissionValidationMeView`` and other REST API endpoints by checking the flag for each scope. Its review showed that these release-blocking endpoints needed more correctness and performance validation than the Verawood schedule allowed. The team chose the approach in `issue #358`_ for that release instead, exposing the raw flag state through a dedicated endpoint and letting the Admin Console apply the simpler #340/#341 rule. Precise filtering for each scope remained future work.

Neither edx-toggles nor edx-platform expose a suitable public API for this client-facing use case. ``/api/toggles/v0/state/`` (`edx_toggles source`_) can expose override data, but it requires Django staff/admin access and exposes flag state broadly (not just ``authz.enable_course_authoring``). ``WaffleFlagOrgOverrideModel.override_value(name, key)`` and its course-level counterpart (`waffle_utils models source`_) each answer for one specific org or course, not "which orgs/courses have an override."

Decision
********

1. Add ``GET /api/authz/v1/waffle-flag-states/``, backed by ``openedx_authz.utils.get_waffle_flag_states()``, returning the flag's global state plus every org and course that currently has an active override, split into 'on' and 'off' lists.
2. The admin-console MFE decides what to show using this response, applying the #340/#341 rule for this release.
3. For Verawood, use this solution instead of the approach explored in PR #361. The per-scope logic in that PR (``is_scope_visible`` and ``has_visible_scope``) remains available on its branch for later work.
4. Filtering REST API results for each specific course or organization remains an open problem. Given the release timeline and the risk PR #361 surfaced, the team chose this more straightforward solution for now.

Consequences
************

#. **Release-blocking endpoints stay untouched.** ``PermissionValidationMeView`` and the other endpoints named in PR #361 keep their existing behavior. This endpoint is additive, isolated, low-risk.
#. **One place answers "what's the flag's state right now."** ``get_waffle_flag_states()`` centralizes the lookup, reusing ``enable_authz_course_authoring()`` for the global tier and querying ``WaffleFlagOrgOverrideModel``/``WaffleFlagCourseOverrideModel`` directly for the org/course tiers, since no public API answers "which orgs/courses have an override."
#. **The MFE bears the filtering complexity.** Applying the #340/#341 "any tier on" rule, and any future precise per-course/per-org filtering, is MFE-side logic from here on.
#. **These override queries scan the whole table, unfiltered by any specific org/course.** For instances with many overrides, this is a full-table read on every call. Not a problem at current scale, but worth revisiting if usage grows (see `issue #360`_).
#. **``openedx_authz.utils`` now depends on** ``common.djangoapps.student.roles.enable_authz_course_authoring`` **and** ``openedx.core.djangoapps.waffle_utils.models``, guarded by the same standalone-import pattern already used elsewhere in this repo (``rest_api/utils.py``, ``handlers.py``). This is a temporary, direct edx-platform dependency, tracked as follow-up work under `issue #360`_ (moving the dependency direction so services depend on ``openedx_authz``).

Rejected Alternatives
**********************

**Enforcing the full per-scope truth table inside release-blocking REST API endpoints (PR #361)**
  Correctness and performance across the whole framework weren't validated in time for a release-blocking change, per PR #361's own comment thread. The simpler #340/#341 rule doesn't need per-scope precision to ship.

**Relying on** ``/api/toggles/v0/state/``
  This edx-toggles endpoint can expose override data, but it requires Django staff/admin access and is not suitable for this use case. It also exposes flag state broadly (not just ``authz.enable_course_authoring``), which is a security risk for this use case.

References
**********

* `ADR 0010`_
* `Issue #340`_
* `Issue #341`_
* `Issue #358`_
* `Issue #360`_
* `PR #361`_
* `PR #361's own comment thread`_
* `A review comment on frontend-app-admin-console#176`_

.. _ADR 0010: 0010-course-authoring-flag.rst
.. _Issue #340: https://github.com/openedx/openedx-authz/issues/340
.. _issue #340: https://github.com/openedx/openedx-authz/issues/340
.. _Issue #341: https://github.com/openedx/openedx-authz/issues/341
.. _issue #341: https://github.com/openedx/openedx-authz/issues/341
.. _Issue #358: https://github.com/openedx/openedx-authz/issues/358
.. _issue #358: https://github.com/openedx/openedx-authz/issues/358
.. _Issue #360: https://github.com/openedx/openedx-authz/issues/360
.. _issue #360: https://github.com/openedx/openedx-authz/issues/360
.. _PR #361: https://github.com/openedx/openedx-authz/pull/361
.. _PR #361's own comment thread: https://github.com/openedx/openedx-authz/pull/361#issuecomment-4967053225
.. _A review comment on frontend-app-admin-console#176: https://github.com/openedx/frontend-app-admin-console/pull/176#issuecomment-4900922914
.. _edx_toggles source: https://github.com/openedx/edx-toggles/blob/master/edx_toggles/toggles/state/internal/report.py
.. _waffle_utils models source: https://github.com/openedx/edx-platform/blob/master/openedx/core/djangoapps/waffle_utils/models.py

0015: Course Authoring Flag Visibility in the REST API
#######################################################

Status
******

**Draft**

Context
*******

``authz.enable_course_authoring`` is a three-tier flag (`ADR 0010`_), where a course override wins over an org override, which in turn wins over the platform default.

A migration is supposed to keep Casbin's role assignments in sync with this flag (`ADR 0011`_, `ADR 0013`_), but in practice it often doesn't, since it's off by default and never runs at all for platform-wide flag changes. That means Casbin can go on holding course data for a course whose flag is off, for as long as nobody runs the migration by hand.

Because of that lag, only the flag itself can answer whether course authoring is on for a given course. Casbin's contents cannot. This is exactly how openedx-platform's own code already treats it, checking the flag directly before it ever touches Casbin.

The flag never governs libraries either, since it only applies to courses; library access keeps using its own separate legacy path, unaffected by it.

The rule this ADR needs to enforce, that course authoring content is visible only when the user has permission and the flag resolves to on, is captured in this truth table, where "None" means no override exists for that tier:

.. list-table::
   :header-rows: 1

   * - Platform Flag
     - Org Override
     - Course Override
     - Effective Authoring State
     - User Has Permission?
     - Show Authoring Roles?
   * - Off
     - None
     - None
     - Off
     - No
     - No
   * - Off
     - None
     - None
     - Off
     - Yes
     - No
   * - On
     - None
     - None
     - On
     - No
     - No
   * - On
     - None
     - None
     - On
     - Yes
     - Yes
   * - Off
     - Force On
     - None
     - On
     - No
     - No
   * - Off
     - Force On
     - None
     - On
     - Yes
     - Yes
   * - On
     - Force On
     - None
     - On
     - No
     - No
   * - On
     - Force On
     - None
     - On
     - Yes
     - Yes
   * - Off
     - Force Off
     - None
     - Off
     - No
     - No
   * - Off
     - Force Off
     - None
     - Off
     - Yes
     - No
   * - On
     - Force Off
     - None
     - Off
     - No
     - No
   * - On
     - Force Off
     - None
     - Off
     - Yes
     - No
   * - Off
     - None
     - Force On
     - On
     - No
     - No
   * - Off
     - None
     - Force On
     - On
     - Yes
     - Yes
   * - On
     - None
     - Force On
     - On
     - No
     - No
   * - On
     - None
     - Force On
     - On
     - Yes
     - Yes
   * - Off
     - None
     - Force Off
     - Off
     - No
     - No
   * - Off
     - None
     - Force Off
     - Off
     - Yes
     - No
   * - On
     - None
     - Force Off
     - Off
     - No
     - No
   * - On
     - None
     - Force Off
     - Off
     - Yes
     - No

This exact cascade is already implemented by ``enable_authz_course_authoring(course_key)`` in ``common.djangoapps.student.roles``, so nothing new needs to be built for it. Only the direct check for org-overrides needs to be added, since that function only accepts a course key and has no public API for checking an org alone.

Decision
********

1. Course-scoped REST API endpoints became flag-aware, starting with ``PermissionValidationMeView``, ahead of and independent from the separate effort to reduce this app's openedx-platform dependencies (`issue #360`_).
2. Staff and superusers get no bypass for flag visibility. The flag's effective state applies the same way to every user.
3. Every permission check backed by Casbin data should be short-circuited by the flag's effective state for that scope, so a stale Casbin grant never surfaces flag-disabled content.
4. Make openedx-platform a temporary dependency of this repo, so that the flag's effective state can be read directly from the same models that openedx-platform itself uses. This is a stopgap until the app is fully decoupled from openedx-platform.

This is implemented by ``is_scope_visible``/``has_visible_scope`` in ``openedx_authz.rest_api.utils``, and applied so far only to ``PermissionValidationMeView``. ``AssignmentsAPIView``, ``RoleUserAPIView``, ``TeamMembersAPIView``, ``TeamMemberAssignmentsAPIView``, ``RoleListView``, and ``ScopesAPIView`` read the same kind of Casbin data and carry the same staleness risk, but wiring them up is follow-up work, not part of this change.

Consequences
************

1. **One place defines flag visibility**, reused by every call site instead of each view re-deriving it or trusting stale Casbin data.
2. **REST API behavior now matches openedx-platform's own enforcement points**, which already treat the flag as the source of truth.
3. **No staff/superuser bypass.** Once an endpoint is wired up, a flag-disabled course stays hidden or denied for every user, regardless of role.
4. **Wired-up endpoints stop returning whatever Casbin holds.** A course-scoped result can now be hidden or denied even though Casbin still has a matching row, whenever the flag is off and a rollback migration hasn't run yet. The REST API and Django Admin's migration status can visibly disagree during that window; this should be called out in user-facing docs about the flag.
5. **Per-row checks cost up to one flag resolution per distinct course/org in a response.** ``enable_authz_course_authoring`` reads models that are ``@request_cached()`` in openedx-platform, so repeat calls for the same course/org within one request are cheap, but a listing spanning N courses across M orgs still costs up to N + M + 1 lookups.
6. **These views depend on** ``enable_authz_course_authoring`` **and** ``WaffleFlagOrgOverrideModel``, guarded by the same standalone-import pattern already used in ``handlers.py`` for ``CourseAccessRole``, so the app keeps loading outside openedx-platform. There's no fail-open fallback: this repo runs as an openedx-platform plugin, so these imports are always available at runtime.

Rejected Alternatives
**********************

**Gating each endpoint as a whole (e.g. 404 for the entire endpoint when the flag is off)**: Every one of these endpoints legitimately continues to serve library data regardless of this flag's state. An endpoint-level gate would hide that data too.

**Relying on Casbin data presence as a proxy for flag state**: ADR 0013 establishes that Casbin content and the flag's effective state can diverge by design (opt-in automatic migration, never triggered for global flag changes). Therefore, treating "the row exists in Casbin" as equivalent to "the flag is on" is wrong and would break the truth table above.

References
**********

* `ADR 0010`_
* `ADR 0011`_
* `ADR 0013`_
* `issue #360`_

.. _ADR 0010: 0010-course-authoring-flag.rst
.. _ADR 0011: 0011-course-authoring-migration-process.rst
.. _ADR 0013: 0013-course-authoring-automatic-migration.rst
.. _0013: 0013-course-authoring-automatic-migration.rst
.. _issue #360: https://github.com/openedx/openedx-authz/issues/360

0016: REST API Domain Ownership Boundary
#########################################

Status
******

**Draft**

Context
*******

``openedx_authz.rest_api`` contains both reusable authorization endpoints and endpoints tailored to a specific Admin Console workflow. That difference in audience and shape does not, by itself, determine which domain owns an endpoint. Issue #360 raised the need for a clearer boundary after `PR #361`_ proposed making ``PermissionValidationMeView`` inspect a course-authoring flag stored in openedx-platform.

An audit of all ten endpoints in ``openedx_authz.rest_api.v1`` classified each one against Open edX's existing domain vocabulary, instead of by who calls it today:

- The `edX DDD Bounded Contexts`_ documentation classifies Open edX's subdomains as core, supporting, or generic.
- `ADR 0018 in openedx-events`_ classifies authorization as a supporting subdomain, the same tier as Analytics. Both are independent of any single application, and both are consumed across learning, content authoring, enterprise, and other areas. ADR 0018 also establishes that a UI surface aggregating tasks from several domains, such as an admin console, is not itself a domain: "'Admin' describes a user role and an interface where tasks from multiple domains are aggregated, the tasks themselves belong to their respective domains."

The audit therefore separates two independent questions:

- **Domain ownership:** Does the endpoint expose authorization data, such as roles, permissions, assignments, or scopes?
- **Package placement:** Is the endpoint reusable, or is it tailored to an Admin Console workflow?

Seven of the ten endpoints expose authorization data. Their domain ownership does not change when an Admin Console-specific response shape makes a separate package useful. ``WaffleFlagStatesAPIView`` exposes the state of a course-authoring flag instead, and this ADR does not need to decide which domain should own that flag; it only establishes that authorization does not. The ownership of ``UserValidationAPIView`` and ``AdminConsoleOrgsAPIView`` also remains unresolved because it is not necessary to settle the flag boundary.

Decision
********

1. Authorization owns endpoints that expose roles, permissions, assignments, or scopes. This remains true whether an endpoint is reusable or tailored to one screen.
2. The five endpoints tailored to Admin Console workflows (``AdminConsoleOrgsAPIView``, ``ScopesAPIView``, ``TeamMembersAPIView``, ``TeamMemberAssignmentsAPIView``, and ``AssignmentsAPIView``) move to ``openedx_authz/rest_api/v1/admin_console/``. This is a code-organization boundary, not a new domain boundary.
3. The reusable endpoints ``PermissionValidationMeView``, ``RoleUserAPIView``, and ``RoleListView`` remain in ``openedx_authz/rest_api/v1/views.py``. Their guarantee is that they answer "what can this subject do" identically regardless of caller. Their own code must not depend on another domain's concept, the course-authoring flag included, that would make the answer depend on who's asking, breaking the guarantee for every other consumer. They may call a domain-neutral extension point that a separate, optional implementation elsewhere fills in; `ADR 0018 (cross-domain filtering)`_ establishes that mechanism.
4. Authorization endpoints' own code must not compute or expose data owned by another domain. ``WaffleFlagStatesAPIView`` remains the sole endpoint that does so directly. `ADR 0018 (cross-domain filtering)`_ documents a second, isolated exception to this rule, an opt-in filter implementation that computes course-authoring visibility without any generic endpoint depending on it; that exception does not extend to the endpoints' own code, only to the separate, disabled-by-default module that ADR names.
5. This ADR does not decide the domain ownership of ``UserValidationAPIView`` or ``AdminConsoleOrgsAPIView``. They retain the package placement described above until that question is resolved separately.

Example, the package layout decision 2 produces::

   openedx_authz/rest_api/v1/
       views.py               # PermissionValidationMeView, RoleUserAPIView, RoleListView, UserValidationAPIView
       admin_console/
           views.py           # AdminConsoleOrgsAPIView, ScopesAPIView, TeamMembersAPIView,
                               # TeamMemberAssignmentsAPIView, AssignmentsAPIView
       course_authoring/
           views.py           # WaffleFlagStatesAPIView

Consequences
************

1. Future proposals cannot add another domain's logic or data to an authorization endpoint without revisiting this decision.
2. Admin Console-specific endpoints have a clear package boundary without treating the Admin Console as a domain.
3. The ownership of ``UserValidationAPIView`` and ``AdminConsoleOrgsAPIView`` remains open.
4. The package move does not change any URLs, so ``frontend-app-admin-console`` is unaffected.
5. This holds even while openedx-authz has few consumers and one exception looks cheap. `openedx_catalog`_, a generic library in openedx-core, defers the same kind of decision rather than building it early. Its API docstring says it "does not yet provide any 'list courses' methods" because visibility depends on "instance-specific logic (e.g. enterprise, subscriptions, white labelling)," left for a future pluggable extension point instead of the generic API absorbing it now. Taking on one consumer's condition today adds a responsibility the framework doesn't own, and makes the API harder to keep generic as more consumers arrive.

Rejected Alternatives
*********************

**Treating the Admin Console as its own domain, on par with authorization or Course Authoring.**
Per `ADR 0018 in openedx-events`_, a UI surface that aggregates tasks from several domains is not itself a domain; the tasks it aggregates belong to whichever domain already owns them. Classifying the Admin Console as a domain would misattribute ownership of tasks (role assignment, permission checks) that belong to authorization, and introduce vocabulary the rest of the Open edX architecture doesn't use.

**Moving the five Admin Console endpoints out of openedx-authz entirely, into a different repository or application.**
Their data (roles, permissions, assignments, scopes) is authorization's own. A non-reusable shape is a package-organization concern, not a reason to relocate authorization's own data to a different codebase.

References
**********

* `edX DDD Bounded Contexts`_
* `ADR 0018 in openedx-events`_
* `ADR 0015`_
* `ADR 0018 (cross-domain filtering)`_
* `Issue #360`_
* `PR #361`_
* `openedx_catalog`_

.. _edX DDD Bounded Contexts: https://openedx.atlassian.net/wiki/spaces/AC/pages/663224968/edX+DDD+Bounded+Contexts
.. _ADR 0018 in openedx-events: https://github.com/openedx/openedx-events/blob/main/docs/decisions/0018-supporting-subdomain-modules.rst
.. _ADR 0015: 0015-expose-course-authoring-waffle-flag-state-via-rest-api.rst
.. _ADR 0018 (cross-domain filtering): 0018-cross-domain-filtering-via-openedx-filters.rst
.. _Issue #360: https://github.com/openedx/openedx-authz/issues/360
.. _PR #361: https://github.com/openedx/openedx-authz/pull/361
.. _openedx_catalog: https://github.com/openedx/openedx-core/blob/main/src/openedx_catalog/api.py

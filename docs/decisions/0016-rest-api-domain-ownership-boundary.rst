0016: REST API Ownership and Package Layout
############################################

Status
******

**Draft**

Context
*******

This ADR applies domain-driven design to make the responsibility and placement of REST API code easier to decide in future work. The boundary keeps application-specific rules out of reusable authorization endpoints, gives reviewers a consistent way to place new code, and makes temporary integrations easier to find and remove later.

``openedx_authz.rest_api`` currently keeps all API views in one ``views.py`` module. Some endpoints provide authorization data that several applications can use, some have request and response formats made for the Admin Console, and one exposes a course-authoring flag.

`PR #361`_ explored adding course-authoring flag checks to reusable authorization endpoints. That work raised two related questions. We need to know which concerns belong to authorization, and we need a package layout that makes those boundaries visible in the code.

The `edX DDD Bounded Contexts`_ documentation supports separating code by responsibility. `ADR 0018 in openedx-events`_ describes authorization as a supporting part of the system and explains that an admin interface can combine work from several areas without owning all of those responsibilities.

We reviewed the ten endpoints in ``openedx_authz.rest_api.v1``. Seven query or manage authorization data:

* ``PermissionValidationMeView``
* ``RoleUserAPIView``
* ``RoleListView``
* ``ScopesAPIView``
* ``TeamMembersAPIView``
* ``TeamMemberAssignmentsAPIView``
* ``AssignmentsAPIView``

``WaffleFlagStatesAPIView`` reads and returns a course-authoring flag. It is a temporary exception in this repository because the data is not authorization data. `ADR 0015`_ records why the endpoint exists, while the formal ownership of the flag remains open.

The ownership of ``UserValidationAPIView`` and ``AdminConsoleOrgsAPIView`` also remains open. We do not need to resolve those questions before separating authorization data from course-authoring data or placing the current endpoints.

Ownership and placement answer different questions. Ownership describes what an endpoint is responsible for and where its data comes from, while placement describes where its code belongs in this repository. For example, an assignment endpoint can return a username and a course scope, but its purpose is to query role assignments from Casbin, the authorization data store. Authorization therefore owns it. The Admin Console may use that endpoint, but it does not become the owner of the assignment data.

Decision
********

1. Authorization owns an endpoint when its main purpose is to query or manage authorization roles, permissions, assignments, or scopes.
2. An authorization endpoint that serves several applications must expose the same authorization behavior to all of them. Its code must not contain course-authoring rules or read course-authoring data directly.
3. A reusable authorization endpoint may call a general hook before returning its data. A separate implementation can then apply a rule based on data outside authorization without adding that rule to the endpoint itself. `ADR 0017 (authorization result extension)`_ defines this mechanism for course-authoring visibility.
4. Place code according to these rules:

   * Keep a reusable authorization endpoint in ``rest_api/v1/views.py``.
   * Put an authorization endpoint made for one application in a package named after that application. The Admin Console endpoints therefore belong in ``admin_console/``.
   * Put a temporary endpoint that exposes data from another area in a package named after that area. ``WaffleFlagStatesAPIView`` therefore belongs in ``course_authoring/``, even though the Admin Console uses it.
   * When the last two rules both appear to apply, the data exposed by the endpoint determines its placement. This keeps exceptions to the authorization boundary visible.

5. Keep supporting code with the package that uses it. If more than one package uses the code, place it in their closest common parent directory. For example, code shared by ``admin_console/`` and ``course_authoring/`` belongs in ``rest_api/v1/``.
6. Move these five Admin Console endpoints to ``openedx_authz/rest_api/v1/admin_console/``:

   * ``AdminConsoleOrgsAPIView``
   * ``ScopesAPIView``
   * ``TeamMembersAPIView``
   * ``TeamMemberAssignmentsAPIView``
   * ``AssignmentsAPIView``

   ``AdminConsoleOrgsAPIView`` moves with this group because its API is made for the Admin Console. This placement does not settle who owns its organization data.

7. Keep ``PermissionValidationMeView``, ``RoleUserAPIView``, ``RoleListView``, and ``UserValidationAPIView`` in ``openedx_authz/rest_api/v1/views.py``.
8. Move ``WaffleFlagStatesAPIView`` to ``openedx_authz/rest_api/v1/course_authoring/``. The package name describes the data that the endpoint exposes without settling who formally owns the flag.

The proposed layout is shown below.

.. code-block:: text

   openedx_authz/rest_api/v1/
       views.py               # Reusable authorization endpoints
       admin_console/
           views.py           # APIs made for Admin Console workflows
       course_authoring/
           views.py           # WaffleFlagStatesAPIView

Consequences
************

1. Reviewers can place future endpoints by checking what they do, which data they read, and whether their APIs are reusable or made for one application.
2. Rules based on data outside authorization, such as the course-authoring flag, remain separate from reusable endpoint code. A new rule must use a general hook or a later ADR must change this boundary.
3. Application-specific serializers, filters, and views can change without adding those details to the reusable API modules.
4. Temporary integrations have a named package, which makes their code and dependencies easier to find when the integration changes or is removed.
5. The endpoint moves will not change their URLs, so clients will not need endpoint URL changes.
6. ``WaffleFlagStatesAPIView`` will remain a named exception until `Issue #377`_ removes it.
7. The ownership of ``UserValidationAPIView`` and ``AdminConsoleOrgsAPIView`` will remain open.

Rejected Alternatives
*********************

**Keeping all views in one module**
  The module would continue to hide the difference between reusable authorization APIs, Admin Console-specific APIs, and the temporary course-authoring endpoint.

**Deciding placement separately for each endpoint**
  Similar endpoints could then follow different placement rules, and reviewers would have no shared test for new code.

**Grouping every endpoint only by the application that uses it**
  This would place ``WaffleFlagStatesAPIView`` under ``admin_console/`` and hide that it exposes course-authoring data as an exception to the authorization boundary.

**Moving the five Admin Console endpoints to another repository or application**
  Four of these endpoints query authorization roles, assignments, or scopes. Their Admin Console-specific APIs justify a separate package, but the authorization code still belongs in this repository. The ownership of ``AdminConsoleOrgsAPIView`` remains open.

**Adding application-specific visibility rules to reusable endpoint code**
  This would make reusable authorization code interpret data that authorization does not own. A general hook keeps the rule in a separate implementation, and `openedx_catalog`_ follows a related approach for installation-specific visibility rules.

References
**********

* `edX DDD Bounded Contexts`_
* `ADR 0018 in openedx-events`_
* `ADR 0015`_
* `ADR 0017 (authorization result extension)`_
* `Issue #377`_
* `PR #361`_
* `openedx_catalog`_

.. _edX DDD Bounded Contexts: https://openedx.atlassian.net/wiki/spaces/AC/pages/663224968/edX+DDD+Bounded+Contexts
.. _ADR 0018 in openedx-events: https://github.com/openedx/openedx-events/blob/main/docs/decisions/0018-supporting-subdomain-modules.rst
.. _ADR 0015: 0015-expose-course-authoring-waffle-flag-state-via-rest-api.rst
.. _ADR 0017 (authorization result extension): 0017-cross-domain-filtering-via-openedx-filters.rst
.. _Issue #377: https://github.com/openedx/openedx-authz/issues/377
.. _PR #361: https://github.com/openedx/openedx-authz/pull/361
.. _openedx_catalog: https://github.com/openedx/openedx-core/blob/main/src/openedx_catalog/api.py

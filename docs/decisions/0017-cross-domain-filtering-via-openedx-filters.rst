0017: Extend Authorization Results without Domain-Specific Dependencies
########################################################################

Status
******

**Proposed** *2026-07-31*

Context
*******

Authorization endpoints need a maintainable way to apply visibility rules without depending on code or concepts owned by another domain. This allows the reusable endpoints to remain domain-neutral and avoid accumulating branches for each application-specific rule. Visibility of roles based on a Waffle flag is one example of this need. The extension must also be easy to disable, replace, or remove as those rules change over time.

The reusable endpoints in ``openedx-authz`` serve more than one application. Course authoring is one consumer of the authorization framework, but future applications can use the same assignment APIs for similar purposes. `ADR 0016`_ therefore keeps course-authoring flags and other application-specific rules out of those endpoints.

`PR #361`_ explored checking ``authz.enable_course_authoring`` directly in ``PermissionValidationMeView``. This would make the view understand a course-authoring concept, while similar requirements from other domains would add more branches to the same code. Testing the authorization endpoints would then require state from those domains, and removing one behavior would require another change to the shared views.

These visibility requirements therefore need a backend solution that does not add domain-specific dependencies. `ADR 0015`_ records the temporary Verawood approach, in which the Admin Console reads the course-authoring flag and hides data in the client. Client-side filtering is not enough for paginated responses because the server calculates the count and selects the page before the client removes hidden items. The optional synchronization in `ADR 0013`_ can keep authorization data aligned with the flag, but deployments that do not enable it can return assignments that are no longer visible.

We need an extension point between the reusable endpoint and the domain-specific visibility rule. The endpoint should provide authorization data as input, let a separately owned implementation process it, and then use the returned data as its output. The endpoint must not know which rule ran or how that rule represented its decision.

Open edX Filters provides this input, process, and output model. It also leaves the input unchanged when no implementation is configured, which allows a deployment to disable or replace a visibility rule without changing the reusable endpoint code.

Decision
********

1. Add one domain-neutral Open edX Filter named ``AuthorizationDataRequested``. Reusable authorization endpoints will depend only on this filter and its contract.
2. The filter contract will follow this flow:

   * **Input:** authorization results and the request context that a configured implementation may need.
   * **Process:** each configured implementation applies the visibility rules that it owns.
   * **Output:** the processed authorization results, which the endpoint uses without further interpretation.

3. The endpoint will call the filter before pagination, counting, or other work that must use only visible data.
4. A configured implementation owns the complete visibility decision for every item it receives. This includes whether to keep, change, or remove an item while preserving the response contract of the calling endpoint. The reusable endpoint will not repeat any part of that decision.
5. Visibility based on the Waffle flag will be implemented separately from the reusable endpoints and placed in the ``course_authoring`` package defined by `ADR 0016`_. This implementation may depend on the flag state, while the neutral filter and reusable endpoints may not.
6. If no implementation is configured, the filter will return its input unchanged. Deployments can enable, replace, or remove the Waffle flag behavior through filter configuration without editing the reusable endpoints.

Examples
********

The same flow applies to every endpoint that uses the filter:

.. code-block:: text

   Authorization results
           |
           v
   AuthorizationDataRequested
           |
           v
   Configured visibility implementation
           |
           v
   Processed results
           |
           v
   Endpoint continues with the result

The following examples illustrate that flow without defining how an implementation must handle every case.

.. list-table::
   :header-rows: 1
   :widths: 18 22 28 18 22

   * - Example
     - Input
     - Process
     - Output
     - Caller
   * - Assignment list
     - Visible assignment and hidden assignment
     - The course-authoring implementation applies its rule
     - Visible assignment
     - Paginates the output
   * - Permission validation
     - Permission results for the requested scopes
     - The implementation applies its rule and preserves the API contract
     - Final permission results
     - Returns the output without interpreting it
   * - No configured implementation
     - Authorization results
     - No change
     - The original authorization results
     - Continues with its existing behavior

Pending
*******

The Waffle visibility rule applies only to course scopes. It must not filter organization rows or hide organizations needed for library scopes.

Before removing the temporary flag-state endpoint, we need to decide how the Admin Console obtains organizations that contain visible courses. It could derive them from backend-filtered course scopes or use an API that explicitly returns organizations for visible course scopes. This decision is part of the Willow work. Until it is resolved, ``AdminConsoleOrgsAPIView`` will not use this filter.

``PermissionValidationMeView`` also accepts requests without a scope. These requests ask whether the user has a permission in any scope, but they do not provide the course or library identifiers that a visibility implementation needs. Before removing the temporary flag-state endpoint, we need to decide whether these requests should provide candidate scopes, use a separate domain-level visibility result, or remain outside this filter. This decision is also part of the Willow work wherever the Admin Console uses an unscoped permission result as a course-authoring visibility check.

Consequences
************

1. ``openedx-filters`` will become a dependency of this repository, but reusable endpoints will not gain dependencies on course-authoring code or state.
2. Each domain-specific implementation will own its visibility rules and how those rules affect the filter output.
3. New visibility requirements can use the same neutral contract without adding domain-specific branches to reusable endpoints.
4. A deployment can replace or remove a visibility implementation without changing the reusable endpoint code.
5. Filtering before pagination will keep counts, pages, and returned results consistent for deployments that enable the course-authoring implementation.
6. The generic organization list will remain unaffected by the course-authoring rule while the pending organization-filter decision is resolved.
7. Unscoped permission requests will keep their current behavior while the pending decision for those requests is resolved.

Rejected Alternatives
*********************

**Adding visibility checks to reusable endpoint code**
  This would make authorization depend on concepts owned by other domains. The shared views would accumulate a new branch for each application-specific rule.

**Letting the endpoint interpret the filter result**
  The endpoint would still need to understand what a domain-specific decision means. The configured implementation must return the final result that the endpoint can use directly.

**Leaving all filtering to the calling application**
  Client-side filtering can produce incorrect counts and incomplete pages because it runs after server-side pagination.

**Relying only on data synchronization**
  Synchronization remains optional and may not run in every deployment. It also couples visibility to stored authorization data instead of allowing the owning domain to apply its current rule when data is requested.

References
**********

* `ADR 0013`_
* `ADR 0015`_
* `ADR 0016`_
* `PR #361`_
* `frontend-app-admin-console PR #176`_

.. _ADR 0013: 0013-course-authoring-automatic-migration.rst
.. _ADR 0015: 0015-expose-course-authoring-waffle-flag-state-via-rest-api.rst
.. _ADR 0016: 0016-rest-api-domain-ownership-boundary.rst
.. _PR #361: https://github.com/openedx/openedx-authz/pull/361
.. _frontend-app-admin-console PR #176: https://github.com/openedx/frontend-app-admin-console/pull/176

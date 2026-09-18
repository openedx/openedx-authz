"""
Pipeline step implementing course-authoring visibility for ``AuthorizationDataRequested``.

This is the isolated, opt-in implementation of the exception documented in
``docs/decisions/0016-rest-api-domain-ownership-boundary.rst`` and
``docs/decisions/0018-cross-domain-filtering-via-openedx-filters.rst``. It's the only place in
openedx_authz that computes course-authoring-flag visibility, and it's never registered unless a
deployment's ``OPEN_EDX_FILTERS_CONFIG`` explicitly wires it in, typically via a Tutor plugin
patch. Deleting this file and the patch that registers it removes the mechanism entirely; no
endpoint code depends on it existing.
"""

from collections.abc import Iterable

from openedx_filters.filters import PipelineStep

from openedx_authz import api
from openedx_authz.filters import AuthorizationData

SCOPE_NOT_AVAILABLE_ERROR = "scope_not_available"

try:
    # common.djangoapps.student.roles and openedx.core are edx-platform's own modules. This app
    # is an edx-platform plugin, so they're always available at runtime; the imports are only
    # guarded so this module can still load under this repo's own standalone test suite
    # (openedx_authz.settings.test, no edx-platform installed).
    from common.djangoapps.student.roles import enable_authz_course_authoring
    from openedx.core.djangoapps.waffle_utils.models import WaffleFlagOrgOverrideModel
    from openedx.core.toggles import AUTHZ_COURSE_AUTHORING_FLAG
except ImportError:
    enable_authz_course_authoring = None
    WaffleFlagOrgOverrideModel = None
    AUTHZ_COURSE_AUTHORING_FLAG = None


def is_scope_visible(scope: api.ScopeData) -> bool:
    """Return whether a scope is visible under the course-authoring flag.

    - Library and other non-course scopes (e.g. 'lib:DemoX:CSPROB'): always visible.
    - Concrete course (e.g. 'course-v1:DemoX+CS101+2024'): full course/org/platform
      cascade via ``enable_authz_course_authoring(course_key)``.
    - Org-level course glob (e.g. 'course-v1:DemoX+*'): org override, else platform default.
    - Platform-level course glob ('course-v1:*'): platform tier only, no course or org.

    Args:
        scope (ScopeData): A resolved scope instance.

    Returns:
        bool: True if the scope should count as visible.
    """
    if scope.NAMESPACE != api.CourseOverviewData.NAMESPACE:
        return True
    if isinstance(scope, api.CourseOverviewData):
        return enable_authz_course_authoring(scope.course_key)
    if isinstance(scope, api.OrgCourseOverviewGlobData):
        # enable_authz_course_authoring only accepts a course key, and there's no public
        # edx-platform API to check an org alone, so this checks the org override directly
        # (see issue #360 for follow-up) when asked to check an org-level course glob
        org_override = WaffleFlagOrgOverrideModel.override_value(AUTHZ_COURSE_AUTHORING_FLAG.name, scope.org)
        if org_override == WaffleFlagOrgOverrideModel.ALL_CHOICES.on:
            return True
        if org_override == WaffleFlagOrgOverrideModel.ALL_CHOICES.off:
            return False
    return enable_authz_course_authoring()


class CourseAuthoringVisibilityFilter(PipelineStep):
    """Applies course-authoring visibility to items from ``AuthorizationDataRequested``.

    Permission results have an optional ``scope``. Role assignments have ``scopes``,
    and role removals have one ``scope``. Hidden scopes affect each kind of data differently:

    - ``scope`` is absent or ``None`` (an any-scope check): left untouched. There's no single scope
      to check visibility against, and no candidate list is provided.
    - Permission results are kept, with ``allowed`` set to ``False`` for hidden scopes.
    - Role assignments and removals exclude hidden scopes or users and return an error for each
      affected user/scope pair.
    """

    def run_filter(  # pylint: disable=arguments-differ
        self,
        items: AuthorizationData,
        **kwargs,
    ) -> dict:
        """Apply course-authoring visibility to permission results or role changes.

        Args:
            items (AuthorizationData): Permission results or validated role assignment
                or removal data, passed under the pipeline's ``items`` keyword.
                Supported shapes include:

                - Permission results, with a concrete scope or no ``scope`` for an
                  any-scope check::

                      [
                          {
                              "action": "courses.manage_course_team",
                              "scope": "course-v1:DemoX+CS101+2024",
                              "allowed": true
                          },
                          {
                              "action": "courses.manage_course_team",
                              "allowed": true
                          }
                      ]

                - Validated role assignments, with a list of scopes::

                      {
                          "role": "<role identifier>",
                          "users": [
                              "alice"
                          ],
                          "scopes": [
                              "course-v1:DemoX+CS101+2024",
                              "course-v1:DemoX+*"
                          ]
                      }

                - Validated role removals, with a single scope::

                      {
                          "role": "<role identifier>",
                          "users": [
                              "alice"
                          ],
                          "scope": "course-v1:DemoX+CS101+2024"
                      }

            **kwargs: Additional pipeline arguments, unused by this step.

        Returns:
            dict: Filtered ``items`` in the original shape, plus ``errors`` for role changes.
        """
        if isinstance(items, dict):
            if "scopes" in items:
                return self._filter_role_assignments(items)
            return self._filter_role_removals(items)
        return self._filter_permission_results(items)

    @staticmethod
    def _hidden_scopes(scopes: Iterable[str | None]) -> set[str]:
        """Find scopes hidden by the course-authoring flag.

        Args:
            scopes (Iterable[str | None]): External scope keys. None represents an
                any-scope check and is skipped.

        Returns:
            set[str]: Scope keys hidden by the flag.
        """
        return {
            scope
            for scope in scopes
            if scope and not is_scope_visible(api.ScopeData(external_key=scope))
        }

    def _filter_permission_results(self, permission_results: list[dict]) -> dict:
        """Keep every permission result, denying those whose scopes are hidden.

        Args:
            permission_results (list[dict]): Permission checks with required ``allowed`` and an
                optional ``scope``. Other fields, such as ``action``, are preserved.

        Returns:
            dict: ``items`` containing all results in order, with ``allowed=False``
                for hidden scopes. Any-scope results are unchanged.
        """
        hidden = self._hidden_scopes(result.get("scope") for result in permission_results)
        return {
            "items": [
                {**result, "allowed": False} if result.get("scope") in hidden else result
                for result in permission_results
            ]
        }

    def _filter_role_assignments(self, assignment_data: dict) -> dict:
        """Exclude hidden scopes from the assignment batch.

        Args:
            assignment_data (dict): Validated ``role``, ``users`` (usernames or emails),
                and ``scopes`` (external scope keys) for a role assignment batch.

        Returns:
            dict: ``items`` with only visible ``scopes``, in order, and ``errors`` for
                each hidden scope/user pair.
        """
        scopes = assignment_data["scopes"]
        hidden = self._hidden_scopes(scopes)
        return {
            "items": {**assignment_data, "scopes": [scope for scope in scopes if scope not in hidden]},
            "errors": self._role_change_errors(
                assignment_data["users"], (scope for scope in scopes if scope in hidden)
            ),
        }

    def _filter_role_removals(self, removal_data: dict) -> dict:
        """Skip all removals when the batch's single scope is hidden.

        Args:
            removal_data (dict): Validated ``role``, ``users`` (usernames or emails),
                and one ``scope`` (an external scope key) for a role removal batch.

        Returns:
            dict: ``items`` with ``users`` cleared if the scope is hidden, and ``errors``
                for each affected user. Otherwise, unchanged data and no errors.
        """
        hidden = self._hidden_scopes([removal_data["scope"]])
        return {
            "items": {**removal_data, "users": [] if hidden else removal_data["users"]},
            "errors": self._role_change_errors(removal_data["users"], hidden),
        }

    @staticmethod
    def _role_change_errors(user_identifiers: list[str], hidden_scopes: Iterable[str]) -> list[dict]:
        """Build one error per affected user/scope pair.

        Args:
            user_identifiers (list[str]): Usernames or email addresses from the batch.
            hidden_scopes (Iterable[str]): Hidden external scope keys, in error order.

        Returns:
            list[dict]: Errors containing ``user_identifier``, ``scope``, and
                ``error="scope_not_available"``, ordered by scope then user as supplied.
        """
        return [
            {
                "user_identifier": user_identifier,
                "scope": scope,
                "error": SCOPE_NOT_AVAILABLE_ERROR,
            }
            for scope in hidden_scopes
            for user_identifier in user_identifiers
        ]

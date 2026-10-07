"""
Pipeline steps implementing course-authoring visibility for REST authorization filters.

This is the isolated, opt-in implementation of the exception documented in
``docs/decisions/0016-rest-api-domain-ownership-boundary.rst`` and
``docs/decisions/0017-cross-domain-filtering-via-openedx-filters.rst``. It's the only place in
openedx_authz that computes course-authoring-flag visibility, and it's never registered unless a
deployment's ``OPEN_EDX_FILTERS_CONFIG`` explicitly wires it in, typically via a Tutor plugin
patch. Deleting this file and the patch that registers it removes the mechanism entirely; no
endpoint code depends on it existing.
"""

from collections.abc import Iterable
from typing import Generic

from openedx_filters.filters import PipelineStep

from openedx_authz import api
from openedx_authz.filters import (
    AuthorizationItems,
    RoleAssignmentItems,
    RoleRemovalItems,
    ValidationItem,
)

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
    """
    Return whether a scope is visible under the course-authoring flag.

    - Library and other non-course scopes (e.g. ``lib:DemoX:CSPROB``): always visible.
    - Concrete course (e.g. ``course-v1:DemoX+CS101+2024``): full course/org/platform
      cascade via ``enable_authz_course_authoring(course_key)``.
    - Org-level course glob (e.g. ``course-v1:DemoX+*``): org override, else platform default.
    - Platform-level course glob (``course-v1:*``): platform tier only, no course or org.

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


class CourseAuthoringVisibilityFilter(PipelineStep, Generic[AuthorizationItems]):
    """Share scope visibility and error accumulation across operations."""

    def run_filter(  # pylint: disable=arguments-differ
        self,
        items: AuthorizationItems,
        errors: list[dict],
        **kwargs,
    ) -> dict:
        """
        Apply the subclass's transformation and preserve earlier pipeline errors.

        Args:
            items (AuthorizationItems): Operation-specific input documented by the subclass.
            errors (list[dict]): Errors from earlier steps, preserved before new errors.
            **kwargs: Additional pipeline arguments, unused by this step.

        Returns:
            dict: Filtered ``items`` in the original shape and accumulated ``errors``.
        """
        filtered_items, new_errors = self._filter_items(items)
        return {"items": filtered_items, "errors": [*errors, *new_errors]}

    def _filter_items(self, items: AuthorizationItems) -> tuple[AuthorizationItems, list[dict]]:
        """
        Define the transformation implemented by each operation-specific step.

        Args:
            items (AuthorizationItems): The operation's input data.

        Returns:
            tuple[AuthorizationItems, list[dict]]: Transformed items in the original
                shape and errors produced by this step, excluding earlier errors.

        Raises:
            NotImplementedError: The subclass has not implemented its transformation.
        """
        raise NotImplementedError("Subclasses must implement their operation's transformation.")

    @staticmethod
    def _hidden_scopes(scopes: Iterable[str | None]) -> set[str]:
        """
        Find scopes hidden by the course-authoring flag.

        Args:
            scopes (Iterable[str | None]): External scope keys. None and empty strings
                represent any-scope checks and are skipped.

        Returns:
            set[str]: Scope keys hidden by the flag.
        """
        return {
            scope
            for scope in scopes
            if scope and not is_scope_visible(api.ScopeData(external_key=scope))
        }

    @staticmethod
    def _role_change_errors(user_identifiers: list[str], hidden_scopes: Iterable[str]) -> list[dict]:
        """
        Build one error per affected user/scope pair.

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


class CourseAuthoringPermissionValidationFilter(CourseAuthoringVisibilityFilter[list[ValidationItem]]):
    """
    Deny permission results whose scopes are hidden, retaining every result.

    Input ``items`` contains computed permission results::

        [
            {
                "action": "courses.manage_course_team",
                "scope": "course-v1:DemoX+CS101+2024",
                "allowed": True,
            },
            {"action": "courses.manage_course_team", "allowed": True},
        ]

    An absent, None, or empty ``scope`` represents an any-scope check and remains
    unchanged. Hidden scopes receive ``allowed=False``; other fields are preserved.
    """

    def _filter_items(self, items: list[ValidationItem]) -> tuple[list[ValidationItem], list[dict]]:
        """
        Set hidden-scope permission results to disallowed without dropping items.

        Args:
            items (list[ValidationItem]): Computed results with ``action``, ``allowed``,
                and an optional ``scope``; see the class docstring for an input example.

        Returns:
            tuple[list[ValidationItem], list[dict]]: Results in their original order,
                with ``allowed=False`` for hidden scopes, and an empty error list.
                Any-scope results and other fields remain unchanged.
        """
        hidden = self._hidden_scopes(item.get("scope") for item in items)
        filtered: list[ValidationItem] = [
            {**item, "allowed": False} if item.get("scope") in hidden else item
            for item in items
        ]
        return filtered, []


class CourseAuthoringRoleAssignmentFilter(CourseAuthoringVisibilityFilter[RoleAssignmentItems]):
    """
    Exclude hidden scopes from validated assignment data before writes.

    Input ``items`` contains a role, user identifiers, and one or more scopes::

        {
            "role": "course_staff",
            "users": ["alice"],
            "scopes": ["course-v1:DemoX+CS101+2024", "course-v1:DemoX+*"],
        }

    Visible scopes remain in their original order. Each rejected user/scope pair
    produces a ``scope_not_available`` error.
    """

    def _filter_items(self, items: RoleAssignmentItems) -> tuple[RoleAssignmentItems, list[dict]]:
        """
        Remove hidden scopes from an assignment batch and report affected users.

        Args:
            items (RoleAssignmentItems): Validated ``role``, ``users`` (usernames or
                emails), and ``scopes``; see the class docstring for an input example.

        Returns:
            tuple[RoleAssignmentItems, list[dict]]: Assignment data containing only
                visible scopes, in order, and one ``scope_not_available`` error for
                each rejected user/scope pair.
        """
        scopes = items["scopes"]
        hidden = self._hidden_scopes(scopes)
        filtered: RoleAssignmentItems = {**items, "scopes": [scope for scope in scopes if scope not in hidden]}
        errors = self._role_change_errors(items["users"], (scope for scope in scopes if scope in hidden))
        return filtered, errors


class CourseAuthoringRoleRemovalFilter(CourseAuthoringVisibilityFilter[RoleRemovalItems]):
    """
    Exclude users from validated removal data when its scope is hidden.

    Input ``items`` contains a role, user identifiers, and a single scope::

        {
            "role": "course_staff",
            "users": ["alice"],
            "scope": "course-v1:DemoX+CS101+2024",
        }

    A hidden scope clears ``users`` and produces a ``scope_not_available`` error
    for each affected user. Visible scopes leave the data unchanged.
    """

    def _filter_items(self, items: RoleRemovalItems) -> tuple[RoleRemovalItems, list[dict]]:
        """
        Clear the removal batch's users when its scope is hidden.

        Args:
            items (RoleRemovalItems): Validated ``role``, ``users`` (usernames or
                emails), and ``scope``; see the class docstring for an input example.

        Returns:
            tuple[RoleRemovalItems, list[dict]]: Removal data with ``users`` cleared
                and one ``scope_not_available`` error per user if the scope is hidden.
                Otherwise, returns unchanged data and no errors.
        """
        hidden = self._hidden_scopes([items["scope"]])
        filtered: RoleRemovalItems = {**items, "users": [] if hidden else items["users"]}
        return filtered, self._role_change_errors(items["users"], hidden)

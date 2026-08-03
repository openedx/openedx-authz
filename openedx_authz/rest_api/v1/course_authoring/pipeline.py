"""
Pipeline step implementing course-authoring visibility for ``AuthorizationDataRequested``.

This is the isolated, opt-in implementation of the exception ``docs/decisions/0016-rest-api-domain-ownership-boundary.rst``
and ``docs/decisions/0018-cross-domain-filtering-via-openedx-filters.rst`` document. It's the only
place in openedx_authz that computes course-authoring-flag visibility, and it's never registered
unless a deployment's ``OPEN_EDX_FILTERS_CONFIG`` explicitly wires it in, typically via a Tutor
plugin patch. Deleting this file and the patch that registers it removes the mechanism entirely;
no endpoint code depends on it existing.
"""

from openedx_filters.filters import PipelineStep

from openedx_authz import api
from openedx_authz.filters import ScopedItem
from openedx_authz.utils import is_user_staff_or_superuser

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


def _is_scope_visible(scope: api.ScopeData) -> bool:
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

    Every item carries a ``scope``. What happens when that scope is hidden depends on the
    item's own shape, not on which endpoint sent it:

    - ``scope`` is ``None`` (an any-scope check): left untouched. There's no single scope
      to check visibility against, and no candidate list is provided.
    - The item has an ``allowed`` key: kept, with ``allowed`` set to ``False`` if hidden.
      Preserves 1:1 correspondence for endpoints like ``PermissionValidationMeView`` that
      must return exactly one result per request.
    - Otherwise: dropped entirely if hidden.

    Staff and superusers see everything, regardless of the flag's state.
    """

    def run_filter(self, items: list[ScopedItem], username: str, **kwargs) -> dict:
        """Apply course-authoring visibility to each item, per its own shape.

        Args:
            items (list[ScopedItem]): serialized items, each carrying a ``scope`` key.
            username (str): the user the items were computed for.

        Returns:
            dict: ``{"items": ...}``, the items that should remain, marked or dropped.
        """
        if is_user_staff_or_superuser(username):
            return {"items": items}

        result = []
        for item in items:
            scope = item.get("scope")
            if scope is None or _is_scope_visible(api.ScopeData(external_key=scope)):
                result.append(item)
            elif "allowed" in item:
                result.append({**item, "allowed": False})
            # else: the scope is hidden and there's no allowed key to flip, drop the item.
        return {"items": result}

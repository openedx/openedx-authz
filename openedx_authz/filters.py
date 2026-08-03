"""
Open edX Filters exposed by openedx_authz's REST API.
"""

from typing import TypedDict

from openedx_filters.tooling import OpenEdxPublicFilter


class ScopedItem(TypedDict):
    """A single item returned by an openedx_authz REST API endpoint.

    Endpoints may include additional keys beyond ``scope`` (e.g. ``role``, ``org``,
    ``username``); ``AuthorizationDataRequested`` and the pipeline steps configured for it
    only ever inspect ``scope``.
    """

    scope: str | None


class ValidationItem(ScopedItem, total=False):
    """A ``ScopedItem`` from a permission-validation response, which also carries ``allowed``."""

    allowed: bool


class AuthorizationDataRequested(OpenEdxPublicFilter):
    """
    Filter used to modify Authorization data before an openedx_authz REST API endpoint returns it.

    Purpose:
        This filter is triggered whenever an openedx_authz REST API endpoint is about to
        return a list of items that each carry a ``scope``, just before serialization,
        allowing another domain to modify that data. Unconfigured (no pipeline step
        registered in ``OPEN_EDX_FILTERS_CONFIG``), every item stays as given; this filter
        carries no assumption about why a pipeline step might change an item.

    Filter Type:
        org.openedx.authz.authorization_data.requested.v1

    Trigger:
        - Repository: openedx/openedx-authz
        - Path: openedx_authz/rest_api/v1/views.py
        - Function or Method: PermissionValidationMeView.post
    """

    filter_type = "org.openedx.authz.authorization_data.requested.v1"

    @classmethod
    def run_filter(cls, items: list[ScopedItem], username: str) -> list[ScopedItem]:
        """Run the pipeline configured for this filter.

        Args:
            items (list[ScopedItem]): serialized items about to be returned, each
                carrying a ``scope`` key.
            username (str): the user the items were computed for, available to any
                pipeline step that needs to make a per-user decision.

        Returns:
            list[ScopedItem]: the items to actually return, as given or modified.
        """
        data = super().run_pipeline(items=items, username=username)
        return data.get("items")

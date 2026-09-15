"""
Open edX Filters exposed by openedx_authz's REST API.
"""

from typing import Any, TypedDict

from django.contrib.auth.models import AbstractBaseUser
from openedx_filters.tooling import OpenEdxPublicFilter


class ScopedItem(TypedDict):
    """
    A scope-bearing item handled by an openedx_authz REST API endpoint.

    Endpoints may include additional keys beyond ``scope`` (e.g. ``role``, ``org``,
    or ``username``).
    """

    scope: str | None


class ValidationItem(ScopedItem, total=False):
    """A ``ScopedItem`` from a permission-validation response, which also carries ``allowed``."""

    allowed: bool


AuthorizationData = list[ScopedItem] | dict[str, Any]


class AuthorizationDataRequested(OpenEdxPublicFilter):
    """
    Filter used to modify scope-bearing Authorization data handled by a REST API endpoint.

    Purpose:
        This filter is triggered when an openedx_authz REST API endpoint needs another
        domain to modify a list of items that each carry a ``scope``. The items may be
        response data or scopes about to be used by an operation. Unconfigured (no pipeline step
        registered in ``OPEN_EDX_FILTERS_CONFIG``), every item stays as given; this filter
        carries no assumption about why a pipeline step might change an item.

    Filter Type:
        org.openedx.authz.authorization_data.requested.v1

    Trigger:
        - Repository: openedx/openedx-authz
        - Path: openedx_authz/rest_api/v1/views.py
        - Function or Method: PermissionValidationMeView.post, RoleUserAPIView.put,
          RoleUserAPIView.delete
    """

    filter_type = "org.openedx.authz.authorization_data.requested.v1"

    @classmethod
    def run_filter(
        cls, items: AuthorizationData, user: AbstractBaseUser
    ) -> tuple[AuthorizationData, list[dict[str, Any]]]:
        """
        Run the pipeline configured for this filter.

        Args:
            items (AuthorizationData): scope-bearing response items or validated
                role-operation data.
            user (AbstractBaseUser): the authenticated user requesting the data,
                available to any pipeline step that needs to make a per-user decision.

        Returns:
            tuple[AuthorizationData, list[dict]]: modified data and errors supplied
                by the configured pipeline.
        """
        data = super().run_pipeline(items=items, user=user)
        return data["items"], data.get("errors", [])

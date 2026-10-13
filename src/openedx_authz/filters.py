"""Open edX Filters exposed by openedx_authz's REST API."""

from typing import Any, Generic, TypedDict, TypeVar

from openedx_filters.tooling import OpenEdxPublicFilter


class ScopedItem(TypedDict, total=False):
    """Optional scope on a permission result; omission represents an any-scope check."""

    scope: str | None


class ValidationItem(ScopedItem):
    """A permission result, including the action and its authorization outcome."""

    action: str
    allowed: bool


class RoleAssignmentItems(TypedDict):
    """Validated input for assigning a role to users in one or more scopes."""

    role: str
    users: list[str]
    scopes: list[str]


class RoleRemovalItems(TypedDict):
    """Validated input for removing a role from users in one scope."""

    role: str
    users: list[str]
    scope: str


AuthorizationItems = TypeVar("AuthorizationItems", list[ValidationItem], RoleAssignmentItems, RoleRemovalItems)


class AuthorizationDataRequested(OpenEdxPublicFilter, Generic[AuthorizationItems]):
    """
    Shared pipeline plumbing for operation-specific REST authorization filters.

    Subclasses declare their payload type and filter identifier. Pipeline steps own
    rejection rules and return data in the original shape, preserving earlier errors.
    """

    @classmethod
    def run_filter(
        cls, items: AuthorizationItems,
    ) -> tuple[AuthorizationItems, list[dict[str, Any]]]:
        """
        Run the operation's configured pipeline with an initially empty error list.

        Args:
            items (AuthorizationItems): Computed permission results or validated role
                change data, using the payload type declared by the subclass.
        Returns:
            tuple[AuthorizationItems, list[dict[str, Any]]]: Items in their original
                shape and accumulated pipeline errors. Without a configured pipeline,
                returns the original items and an empty error list.
        """
        data = super().run_pipeline(items=items, errors=[])
        return data["items"], data["errors"]


class PermissionValidationRequested(AuthorizationDataRequested[list[ValidationItem]]):
    """
    Filter computed permission results before response serialization.

    Each item contains ``action`` and ``allowed``, with an optional ``scope``.

    Trigger:
        ``PermissionValidationMeView.post``, after authorization checks and before
        response serialization.

    Filter Type:
        org.openedx.authz.permission_validation.requested.v1
    """

    filter_type = "org.openedx.authz.permission_validation.requested.v1"


class RoleAssignmentRequested(AuthorizationDataRequested[RoleAssignmentItems]):
    """
    Filter validated ``role``, ``users``, and ``scopes`` before assignment writes.

    Trigger:
        ``RoleUserAPIView.put``, after request validation and before assigning roles.

    Filter Type:
        org.openedx.authz.role_assignment.requested.v1
    """

    filter_type = "org.openedx.authz.role_assignment.requested.v1"


class RoleRemovalRequested(AuthorizationDataRequested[RoleRemovalItems]):
    """
    Filter validated ``role``, ``users``, and ``scope`` before removal writes.

    Trigger:
        ``RoleUserAPIView.delete``, after request validation and before removing roles.

    Filter Type:
        org.openedx.authz.role_removal.requested.v1
    """

    filter_type = "org.openedx.authz.role_removal.requested.v1"

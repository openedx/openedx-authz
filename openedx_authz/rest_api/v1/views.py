"""Views for the Open edX AuthZ REST API."""

import logging

from common.djangoapps.student.models.user import get_user_by_username_or_email
from django.contrib.auth import get_user_model
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from openedx_authz.api.data import ActionData, ScopeData, UserData
from openedx_authz.api.permissions import has_permission
from openedx_authz.api.roles import get_role_definitions_in_scope
from openedx_authz.api.users import (
    assign_role_to_user_in_scope,
    get_user_role_assignments_for_role_in_scope,
    unassign_role_from_user,
)
from openedx_authz.rest_api.v1.serializers import (
    AddUserToRoleWithScopeSerializer,
    ListRolesWithScopeSerializer,
    ListUsersInRoleWithScopeSerializer,
    PermissionValidationSerializer,
    RemoveUserFromRoleWithScopeSerializer,
)

logger = logging.getLogger(__name__)

User = get_user_model()


class PermissionValidationView(APIView):
    """
    Validate permissions for the authenticated user.
    """

    permission_classes = [IsAuthenticated]

    def post(self, request):
        """Validate permissions for the authenticated user."""
        serializer = PermissionValidationSerializer(data=request.data, many=True)
        serializer.is_valid(raise_exception=True)

        username = request.user.username
        subject = UserData(username=username)

        for perm in serializer.validated_data:
            try:
                action = ActionData(name=perm["action"])
                scope = ScopeData(name=perm["scope"])
                allowed = has_permission(subject, action, scope)
                perm["allowed"] = allowed
            except Exception as e:  # pylint: disable=broad-exception-caught
                logger.error(f"Error validating permission for user {username}: {e}")

        return Response(serializer.validated_data, status=status.HTTP_200_OK)


class RoleUserAPIView(APIView):
    """
    APIView for managing users and their roles.
    Handles GET (list), PUT (add), and DELETE (remove) operations.
    """

    permission_classes = [IsAuthenticated]

    def get(self, request):
        """
        Get list of users in the role.
        """
        serializer = ListUsersInRoleWithScopeSerializer(data=request.query_params)
        serializer.is_valid(raise_exception=True)

        role_name = serializer.validated_data["role"]
        scope = serializer.validated_data["scope"]

        response_data = []
        role_assignments = get_user_role_assignments_for_role_in_scope(role_name, scope)
        for assignment in role_assignments:
            # TODO: Should we get all users at once instead of one by one?
            user = get_user_by_username_or_email(assignment.subject.username)
            response_data.append(
                {
                    "username": assignment.subject.username,
                    "full_name": user.profile.name,
                    "email": user.email,
                }
            )

        return Response(response_data, status=status.HTTP_200_OK)

    def put(self, request):
        """
        Add users to the role.
        """
        serializer = AddUserToRoleWithScopeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        completed, errors = [], []
        role_name = serializer.validated_data["role"]
        scope = serializer.validated_data["scope"]

        for user_identifier in serializer.validated_data["users"]:
            try:
                user = get_user_by_username_or_email(user_identifier)
                assign_role_to_user_in_scope(user.username, role_name, scope)
                completed.append({"user": user_identifier, "status": "role_added"})
            except User.DoesNotExist:
                errors.append({"user": user_identifier, "error": "user_not_found"})
            except Exception as e:  # pylint: disable=broad-exception-caught
                logger.error(f"Error assigning role to user {user_identifier}: {e}")
                errors.append({"user": user_identifier, "error": "assignment_failed"})

        response_data = {"completed": completed, "errors": errors}
        return Response(response_data, status=status.HTTP_207_MULTI_STATUS)

    def delete(self, request):
        """
        Remove user role from the role.
        """
        serializer = RemoveUserFromRoleWithScopeSerializer(data=request.query_params)
        serializer.is_valid(raise_exception=True)

        user_identifier = serializer.validated_data["user"]
        role_name = serializer.validated_data["role"]
        scope = serializer.validated_data["scope"]

        try:
            user = get_user_by_username_or_email(user_identifier)
            unassign_role_from_user(user.username, role_name, scope)
            return Response({"message": "Role successfully removed from user"}, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:  # pylint: disable=broad-exception-caught
            logger.error(f"Error removing role from user {user_identifier}: {e}")
            return Response({"error": "Internal server error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class RoleListView(APIView):
    """
    Get list of roles with their permissions for a scope.
    """

    permission_classes = [IsAuthenticated]

    def get(self, request):
        """Get list of roles with their permissions for a library."""
        serializer = ListRolesWithScopeSerializer(data=request.query_params)
        serializer.is_valid(raise_exception=True)

        scope = ScopeData(name=serializer.validated_data["scope"])

        response_data = []
        roles = get_role_definitions_in_scope(scope)

        for role in roles:
            response_data.append(
                {
                    "role": role.name,
                    "permissions": [perm.action.name for perm in role.permissions] if role.permissions else [],
                    # TODO: Get user count using a api function
                    "user_count": 0,
                }
            )

        return Response(response_data, status=status.HTTP_200_OK)

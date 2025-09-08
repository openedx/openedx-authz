"""
Views for openedx_authz DRF API.
"""

from dauthz.core import enforcer
from django.shortcuts import get_object_or_404
from rest_framework import status, viewsets
from rest_framework.response import Response

from .models import Library
from .serializers import LibrarySerializer

enforcer.enable_auto_save(True)


class LibraryViewSet(viewsets.ViewSet):
    """
    A ViewSet for handling Library operations using the Library model.
    Provides all HTTP methods: GET, POST, PUT, PATCH, DELETE
    """

    def list(self, request):
        """
        GET /libraries/
        Return a list of all libraries.
        """
        libraries = Library.objects.all()
        serializer = LibrarySerializer(libraries, many=True)
        return Response({"count": libraries.count(), "results": serializer.data})

    def create(self, request):
        """
        POST /libraries/
        Create a new library.

        Example request body:

        ```json
        {
            "title": "Title 1",
            "org": "org1",
            "slug": "slug1",
            "description": "Description 1"
        }
        ```
        """
        serializer = LibrarySerializer(data=request.data)
        if serializer.is_valid():
            library = serializer.save()
            enforcer.add_policy(
                self.request.user.username,
                f"{self.request.path}{library.id}/",
                "(GET)|(PUT)|(DELETE)|(PATCH)",
            )
            return Response(LibrarySerializer(library).data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def retrieve(self, request, pk=None):
        """
        GET /libraries/{id}/
        Retrieve a specific library by ID.
        """
        library = get_object_or_404(Library, id=pk)
        serializer = LibrarySerializer(library)
        return Response(serializer.data)

    def update(self, request, pk=None):
        """
        PUT /libraries/{id}/
        Update a library completely.
        """
        library = get_object_or_404(Library, id=pk)
        serializer = LibrarySerializer(library, data=request.data)

        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def partial_update(self, request, pk=None):
        """
        PATCH /libraries/{id}/
        Partially update a library.
        """
        library = get_object_or_404(Library, id=pk)
        serializer = LibrarySerializer(library, data=request.data, partial=True)

        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, pk=None):
        """
        DELETE /libraries/{id}/
        Delete a library.
        """
        library = get_object_or_404(Library, id=pk)
        library.delete()
        enforcer.remove_filtered_policy(1, self.request.user.username, f"{self.request.path}{library.id}/", "")

        return Response(
            {"detail": f'Library "{library}" has been deleted.'},
            status=status.HTTP_204_NO_CONTENT,
        )


class AdminRoleAssignmentViewSet(viewsets.ViewSet):
    """
    ViewSet for managing admin role assignments using Casbin.
    """

    def create(self, request):
        """
        POST /admin-roles/
        Assign admin role to a user.

        Example request body:
        ```json
        {
            "username": "john_doe"
        }
        ```
        """
        username = request.data["username"]
        enforcer.add_role_for_user(username, "admin")
        return Response(f"Admin role assigned to user {username}", status=status.HTTP_201_CREATED)

    def destroy(self, request, pk=None):
        """
        DELETE /admin-roles/{username}/
        Remove admin role from a user.
        """
        username = pk
        enforcer.delete_role_for_user(username, "admin")
        return Response(f"Admin role removed from user {username}", status=status.HTTP_204_NO_CONTENT)


class PolicyBulkViewSet(viewsets.ViewSet):
    """
    ViewSet for bulk policy operations using Casbin's add_policies and remove_policies.
    This is a simple testing interface for bulk policy management.
    """

    def create(self, request):
        """
        POST /policy-bulk/
        Add multiple policies at once using add_policies.

        Example request body:
        ```json
        {
            "policies": [
                ["user1", "/api/resource1/", "GET"],
                ["user2", "/api/resource2/", "POST"],
                ["user3", "/api/resource3/", "DELETE"]
            ]
        }
        ```
        """
        policies = request.data.get("policies", [])
        result = enforcer.add_policies(policies)
        return Response(
            {
                "message": "Bulk policy addition completed",
                "success": result,
                "policies_added": len(policies),
                "policies": policies,
            },
            status=status.HTTP_201_CREATED if result else status.HTTP_200_OK,
        )

    def destroy(self, request, pk=None):  # pylint: disable=unused-argument
        """
        DELETE /policy-bulk/remove/
        Remove multiple policies at once using remove_policies.
        Uses request body instead of pk since we need to pass multiple policies.

        Example request body:
        ```json
        {
            "policies": [
                ["user1", "/api/resource1/", "GET"],
                ["user2", "/api/resource2/", "POST"]
            ]
        }
        ```
        """
        policies = request.data.get("policies", [])
        result = enforcer.remove_policies(policies)
        return Response(
            {
                "message": "Bulk policy removal completed",
                "success": result,
                "policies_removed": len(policies),
                "policies": policies,
            },
            status=status.HTTP_204_NO_CONTENT if result else status.HTTP_200_OK,
        )


class PolicySingleViewSet(viewsets.ViewSet):
    """
    ViewSet for single policy operations using Casbin's add_policy and remove_policy.
    Simple testing interface for individual policy management.
    """

    def create(self, request):
        """
        POST /policy-single/
        Add a single policy using add_policy.

        Example request body:
        ```json
        {
            "subject": "user1",
            "object": "/api/resource1/",
            "action": "GET"
        }
        ```
        """
        subject = request.data.get("subject")
        obj = request.data.get("object")
        action = request.data.get("action")
        result = enforcer.add_policy(subject, obj, action)
        return Response(
            {
                "message": "Policy added successfully" if result else "Policy already exists",
                "success": result,
                "policy": [subject, obj, action],
            },
            status=status.HTTP_201_CREATED if result else status.HTTP_200_OK,
        )

    def destroy(self, request, pk=None):  # pylint: disable=unused-argument
        """
        DELETE /policy-single/remove/
        Remove a single policy using remove_policy.

        Example request body:
        ```json
        {
            "subject": "user1",
            "object": "/api/resource1/",
            "action": "GET"
        }
        ```
        """
        subject = request.data.get("subject")
        obj = request.data.get("object")
        action = request.data.get("action")
        result = enforcer.remove_policy(subject, obj, action)
        return Response(
            {
                "message": "Policy removed successfully" if result else "Policy not found",
                "success": result,
                "policy": [subject, obj, action],
            },
            status=status.HTTP_204_NO_CONTENT if result else status.HTTP_404_NOT_FOUND,
        )

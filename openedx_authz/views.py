"""
Views for openedx_authz DRF API.
"""

from dauthz.core import enforcer
from django.shortcuts import get_object_or_404
from rest_framework import status, viewsets
from rest_framework.response import Response

from .models import Library
from .serializers import LibrarySerializer


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
            enforcer.save_policy()
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
        library_title = library.title
        library.delete()
        enforcer.remove_filtered_policy(1, self.request.user.username, f"{self.request.path}{library.id}/", "")
        enforcer.save_policy()

        return Response(
            {"detail": f'Library "{library_title}" has been deleted.'},
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
        enforcer.save_policy()
        return Response(f"Admin role assigned to user {username}", status=status.HTTP_201_CREATED)

    def destroy(self, request, pk=None):
        """
        DELETE /admin-roles/{username}/
        Remove admin role from a user.
        """
        username = pk
        enforcer.delete_role_for_user(username, "admin")
        enforcer.save_policy()
        return Response(f"Admin role removed from user {username}", status=status.HTTP_204_NO_CONTENT)


class UserPermissionViewSet(viewsets.ViewSet):
    """
    ViewSet for managing specific user permissions using Casbin.
    Allows adding or removing specific permissions for users on resources.

    Example:
    ```json
    {
        "username": "john_doe",
        "obj": "/api/libraries/",
        "act": "GET"
    }
    ```
    """

    def create(self, request):
        """
        POST /user-permissions/
        Add a specific permission to a user.

        Example request body:
        ```json
        {
            "username": "john_doe",
            "obj": "/api/libraries/123/",
            "act": "GET"
        }
        ```
        """
        username = request.data.get("username")
        obj = request.data.get("obj")
        act = request.data.get("act")

        if not all([username, obj, act]):
            return Response({"error": "username, obj, and act are required fields"}, status=status.HTTP_400_BAD_REQUEST)

        enforcer.add_policy(username, obj, act)
        enforcer.save_policy()

        return Response(
            {
                "message": f"Permission '{act}' on '{obj}' granted to user '{username}'",
                "username": username,
                "obj": obj,
                "act": act,
            },
            status=status.HTTP_201_CREATED,
        )

    def destroy(self, request, pk=None):
        """
        DELETE /user-permissions/{username}/
        Remove a specific permission from a user.

        Query parameters:
        - obj: The resource path (required)
        - act: The action/method (required)

        Example: DELETE /user-permissions/john_doe/?obj=/api/libraries/123/&act=GET
        """
        username = pk
        obj = request.query_params.get("obj")
        act = request.query_params.get("act")

        if not all([obj, act]):
            return Response({"error": "obj and act query parameters are required"}, status=status.HTTP_400_BAD_REQUEST)

        result = enforcer.remove_policy(username, obj, act)
        enforcer.save_policy()

        if result:
            return Response(
                {
                    "message": f"Permission '{act}' on '{obj}' removed from user '{username}'",
                    "username": username,
                    "obj": obj,
                    "act": act,
                },
                status=status.HTTP_204_NO_CONTENT,
            )
        else:
            return Response(
                {"error": f"Permission not found for user '{username}' on '{obj}' with action '{act}'"},
                status=status.HTTP_404_NOT_FOUND,
            )

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

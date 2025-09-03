"""
Views for openedx_authz DRF API.
"""

from dauthz.core import enforcer
from rest_framework import status, viewsets
from rest_framework.response import Response

from .serializers import LibrarySerializer


def load_policy():
    """
    Load the policy for the openedx_authz Django application.
    """
    # Moving this import outside the function break the code :)
    # from dauthz.core import enforcer  # pylint: disable=import-outside-toplevel

    p_rules = [
        ["anonymous", "/", "(GET)|(POST)"],
        ["admin", "/*", "(GET)|(POST)|(PUT)|(DELETE)|(PATCH)"],
    ]
    g_rules = [
        ["normal_user", "anonymous"],
        ["admin", "normal_user"],
    ]
    enforcer.add_policies(p_rules)
    enforcer.add_grouping_policies(g_rules)
    enforcer.save_policy()
    print("\n\nPolicy loaded...\n\n")


class LibraryViewSet(viewsets.ViewSet):
    """
    A ViewSet for handling Library operations with dummy data.
    Provides all HTTP methods: GET, POST, PUT, PATCH, DELETE
    """

    # Dummy data for OpenedX libraries
    dummy_libraries = [
        {
            "id": "lib:OpenedX:LIBEXAMPLE",
            "org": "OpenedX",
            "slug": "LIBEXAMPLE",
            "title": "Library Example",
            "description": "Example library for demonstration purposes",
            "num_blocks": 15,
            "version": 2,
            "allow_public_read": True,
            "can_edit_library": False,
            "created": "2023-01-15T10:00:00Z",
            "updated": "2024-01-15T10:00:00Z",
        },
        {
            "id": "lib:AXIM:SecondLibrary",
            "org": "AXIM",
            "slug": "SecondLibrary",
            "title": "Second Library Example",
            "description": "Another example library for testing",
            "num_blocks": 8,
            "version": 1,
            "allow_public_read": False,
            "can_edit_library": False,
            "created": "2023-02-20T14:30:00Z",
            "updated": "2024-02-20T14:30:00Z",
        },
        {
            "id": "lib:MITx:PythonLibrary",
            "org": "MITx",
            "slug": "PythonLibrary",
            "title": "Python Programming Library",
            "description": "Library containing Python programming exercises and examples",
            "num_blocks": 25,
            "version": 3,
            "allow_public_read": True,
            "can_edit_library": True,
            "created": "2023-03-10T09:15:00Z",
            "updated": "2024-03-10T09:15:00Z",
        },
        {
            "id": "lib:HarvardX:MathLibrary",
            "org": "HarvardX",
            "slug": "MathLibrary",
            "title": "Mathematics Content Library",
            "description": "",
            "num_blocks": 0,
            "version": 0,
            "allow_public_read": True,
            "can_edit_library": False,
            "created": None,
            "updated": None,
        },
    ]

    def list(self, request):
        """
        GET /libraries/
        Return a list of all libraries.
        """
        print("\n\nListing libraries...\n\n")
        load_policy()
        breakpoint()

        enforcer.enforce("admin", "/libraries/", "(GET)|(POST)|(PUT)|(DELETE)|(PATCH)")

        # Filter by public read access if requested
        allow_public_read = request.query_params.get("allow_public_read")
        libraries = self.dummy_libraries

        if allow_public_read is not None:
            allow_public_read_bool = allow_public_read.lower() in ["true", "1", "yes"]
            libraries = [lib for lib in libraries if lib["allow_public_read"] == allow_public_read_bool]

        # Filter by organization if requested
        org = request.query_params.get("org")
        if org:
            libraries = [lib for lib in libraries if lib["org"].lower() == org.lower()]

        # Search by title if requested
        search = request.query_params.get("search")
        if search:
            libraries = [lib for lib in libraries if search.lower() in lib["title"].lower()]

        return Response({"count": len(libraries), "results": libraries})

    def create(self, request):
        """
        POST /libraries/
        Create a new library.
        """
        serializer = LibrarySerializer(data=request.data)
        if serializer.is_valid():
            # Generate library ID if not provided
            validated_data = serializer.validated_data
            if "id" not in validated_data:
                validated_data["id"] = f"lib:{validated_data['org']}:{validated_data['slug']}"

            new_library = {
                **validated_data,
                "created": "2024-01-01T12:00:00Z",
                "updated": "2024-01-01T12:00:00Z",
            }

            # Add to dummy data (in real app, this would save to database)
            self.dummy_libraries.append(new_library)

            return Response(new_library, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def retrieve(self, request, pk=None):
        """
        GET /libraries/{id}/
        Retrieve a specific library by ID.
        """
        library = next((lib for lib in self.dummy_libraries if lib["id"] == pk), None)

        if library:
            return Response(library)
        else:
            return Response({"detail": "Library not found."}, status=status.HTTP_404_NOT_FOUND)

    def update(self, request, pk=None):
        """
        PUT /libraries/{id}/
        Update a library completely.
        """
        library_index = next((i for i, lib in enumerate(self.dummy_libraries) if lib["id"] == pk), None)

        if library_index is not None:
            serializer = LibrarySerializer(data=request.data)
            if serializer.is_valid():
                # Update the library with new data
                updated_library = {
                    **serializer.validated_data,
                    "created": self.dummy_libraries[library_index]["created"],
                    "updated": "2024-01-01T12:00:00Z",
                }

                self.dummy_libraries[library_index] = updated_library
                return Response(updated_library)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({"detail": "Library not found."}, status=status.HTTP_404_NOT_FOUND)

    def partial_update(self, request, pk=None):
        """
        PATCH /libraries/{id}/
        Partially update a library.
        """
        library_index = next((i for i, lib in enumerate(self.dummy_libraries) if lib["id"] == pk), None)

        if library_index is not None:
            current_library = self.dummy_libraries[library_index].copy()
            serializer = LibrarySerializer(data=request.data, partial=True)

            if serializer.is_valid():
                # Update only the provided fields
                for field, value in serializer.validated_data.items():
                    current_library[field] = value

                current_library["updated"] = "2024-01-01T12:00:00Z"
                self.dummy_libraries[library_index] = current_library

                return Response(current_library)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({"detail": "Library not found."}, status=status.HTTP_404_NOT_FOUND)

    def destroy(self, request, pk=None):
        """
        DELETE /libraries/{id}/
        Delete a library.
        """
        library_index = next((i for i, lib in enumerate(self.dummy_libraries) if lib["id"] == pk), None)

        if library_index is not None:
            deleted_library = self.dummy_libraries.pop(library_index)
            return Response(
                {"detail": f'Library "{deleted_library["title"]}" has been deleted.'},
                status=status.HTTP_204_NO_CONTENT,
            )
        else:
            return Response({"detail": "Library not found."}, status=status.HTTP_404_NOT_FOUND)

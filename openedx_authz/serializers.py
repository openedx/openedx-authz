"""
Serializers for openedx_authz DRF API.
"""

from rest_framework import serializers
from .models import Library


class LibrarySerializer(serializers.ModelSerializer):
    """
    Serializer for OpenedX Library model.
    """

    class Meta:
        model = Library
        fields = [
            "id",
            "org",
            "slug",
            "title",
            "description",
        ]
        read_only_fields = ["id"]

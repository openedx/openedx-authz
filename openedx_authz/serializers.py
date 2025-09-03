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
            "num_blocks",
            "version",
            "allow_public_read",
            "can_edit_library",
            "created",
            "updated",
        ]
        read_only_fields = ["created", "updated"]

    def validate_num_blocks(self, value):
        """
        Validate that num_blocks is not negative.
        """
        if value < 0:
            raise serializers.ValidationError("Number of blocks cannot be negative.")
        return value

    def validate_title(self, value):
        """
        Validate that title is not empty.
        """
        if not value.strip():
            raise serializers.ValidationError("Library title cannot be empty.")
        return value.strip()

    def validate_org(self, value):
        """
        Validate that organization is not empty.
        """
        if not value.strip():
            raise serializers.ValidationError("Organization cannot be empty.")
        return value.strip()

    def validate_slug(self, value):
        """
        Validate that slug is not empty.
        """
        if not value.strip():
            raise serializers.ValidationError("Library slug cannot be empty.")
        return value.strip()

    def validate(self, data):
        """
        Validate that the ID matches the org:slug format if provided.
        """
        if "id" in data and "org" in data and "slug" in data:
            expected_id = f"lib:{data['org']}:{data['slug']}"
            if data["id"] != expected_id:
                raise serializers.ValidationError(
                    f"Library ID should be in format 'lib:ORG:SLUG'. Expected: {expected_id}"
                )
        return data

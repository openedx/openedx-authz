"""Fields serializer for the Open edX AuthZ REST API."""

from rest_framework import serializers


class CommaSeparatedListField(serializers.CharField):
    """Serializer for a comma-separated list of strings."""

    def to_internal_value(self, data):
        """Convert string separated by commas to list of unique items preserving order"""
        return list(dict.fromkeys(item.strip().lower() for item in data.split(",") if item.strip()))

    def to_representation(self, value):
        """Convert list to string separated by commas"""
        return ",".join(value).lower()


class LowercaseCharField(serializers.CharField):
    """Serializer for a lowercase string."""

    def to_internal_value(self, data):
        """Convert string to lowercase"""
        return data.strip().lower()

    def to_representation(self, value):
        """Convert string to lowercase"""
        return value.strip().lower()

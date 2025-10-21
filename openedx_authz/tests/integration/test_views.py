"""Integration tests for openedx_authz views."""


from django.test import TestCase
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient
from django.contrib.auth import get_user_model

from openedx_authz.models.core import ExtendedCasbinRule
from openedx_authz.tests.integration.test_models import create_test_library


User = get_user_model()

class TestRoleAssignmentView(TestCase):
    """Tests for the role assignment view."""

    def setUp(self):
        """Set up the test client and any required data."""
        self.client = APIClient()
        self.url = reverse("openedx_authz:role-assignment")
        self.library_metadata, self.library_key, self.content_library = create_test_library("TestOrg")
        self.role_key = "library_admin"
        # Create User
        self.user_data = {
            "username": "test_user",
            "email": "test_user@example.com"
        }
        self.user = User.objects.create_user(**self.user_data)

    def test_role_assignment_with_extended_model(self):
        """Test role assignment when ExtendedCasbinRule model is in use.

        Expected Results:
        - Role assignment is successful (HTTP 201 Created).
        - An ExtendedCasbinRule is created with the correct scope and subject.
        """
        payload = {
            "user": self.user.username,
            "role": self.role_key,
            "scope": self.library_key,
        }

        response = self.client.post(self.url, payload, format='json')

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn("role_assignment_id", response.data)

        extended_rule = ExtendedCasbinRule.objects.filter(
            subject__user=self.user,
            scope__content_library=self.content_library,
        ).first()
        self.assertIsNotNone(extended_rule)
        self.assertIn(payload["role"], extended_rule.casbin_rule_key)

    def test_role_unassignment_with_extended_model(self):
        """Test role unassignment when ExtendedCasbinRule model is in use.

        Expected Results:
        - Role unassignment is successful (HTTP 204 No Content).
        - The associated ExtendedCasbinRule is deleted.
        - No orphaned ExtendedCasbinRule remains after unassignment.
        """
        payload = {
            "user": self.user.username,
            "role": self.role_key,
            "scope": self.library_key,
        }
        create_response = self.client.post(self.url, payload, format='json')
        self.assertEqual(create_response.status_code, status.HTTP_201_CREATED)
        role_assignment_id = create_response.data["role_assignment_id"]

        unassign_url = reverse("openedx_authz:role-unassignment", args=[role_assignment_id])
        unassign_response = self.client.delete(unassign_url)

        self.assertEqual(unassign_response.status_code, status.HTTP_204_NO_CONTENT)

        extended_rule = ExtendedCasbinRule.objects.filter(
            subject__user=self.user,
            scope__content_library__id=self.content_library.id,
        ).first()
        self.assertIsNone(extended_rule)

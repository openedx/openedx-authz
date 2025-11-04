"""Integration tests for openedx_authz views."""

import os
import uuid
from urllib.parse import urlencode

import casbin
import pytest
from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient

from openedx_authz import ROOT_DIRECTORY
from openedx_authz.api.users import assign_role_to_user_in_scope
from openedx_authz.engine.enforcer import AuthzEnforcer
from openedx_authz.engine.utils import migrate_policy_between_enforcers
from openedx_authz.models.core import ExtendedCasbinRule
from openedx_authz.tests.integration.test_models import create_test_library

User = get_user_model()


@pytest.mark.integration
class TestRoleAssignmentView(TestCase):
    """Tests for the role assignment view."""

    @classmethod
    def setUpClass(cls):
        """Set up test class - seed database with policies."""
        super().setUpClass()
        # Seed the database with policies from the policy file
        # This loads the policy definitions (p, g rules) that define what permissions each role has
        global_enforcer = AuthzEnforcer.get_enforcer()
        global_enforcer.load_policy()

        # Use absolute paths based on the package ROOT_DIRECTORY
        model_conf = os.path.join(ROOT_DIRECTORY, "engine", "config", "model.conf")
        authz_policy = os.path.join(ROOT_DIRECTORY, "engine", "config", "authz.policy")

        migrate_policy_between_enforcers(
            source_enforcer=casbin.Enforcer(model_conf, authz_policy),
            target_enforcer=global_enforcer,
        )

    def setUp(self):
        """Set up the test client and any required data."""
        self.client = APIClient()
        self.url = reverse("openedx_authz:openedx_authz:role-user-list")
        self.library_metadata, self.library_key, self.content_library = create_test_library("TestOrg")
        self.role_key = "library_admin"

        # Create random users to avoid conflicts in persistent database
        unique_id = uuid.uuid4().hex[:8]
        self.user = User.objects.create_user(username=f"test_user_{unique_id}", email=f"test_{unique_id}@example.com")
        self.admin_user = User.objects.create_user(
            username=f"admin_user_{unique_id}", email=f"admin_{unique_id}@example.com", is_staff=True, is_superuser=True
        )

        assign_role_to_user_in_scope(
            user_external_key=self.admin_user.username,
            role_external_key=self.role_key,
            scope_external_key=str(self.library_key),
        )
        self.client.force_authenticate(user=self.admin_user)

    def test_role_assignment_with_extended_model(self):
        """Test role assignment when ExtendedCasbinRule model is in use.

        Expected Results:
        - Role assignment is successful (HTTP 207 Multi-Status).
        - An ExtendedCasbinRule is created with the correct scope and subject.
        """
        payload = {
            "users": [self.user.username],
            "role": self.role_key,
            "scope": str(self.library_key),
        }

        response = self.client.put(self.url, payload, format="json")

        self.assertEqual(response.status_code, status.HTTP_207_MULTI_STATUS)
        self.assertEqual(len(response.data["completed"]), 1)

        extended_rule = ExtendedCasbinRule.objects.filter(
            subject__usersubject__user=self.user,
            scope__contentlibraryscope__content_library=self.content_library,
        ).first()
        self.assertIsNotNone(extended_rule)
        self.assertIn(payload["role"], extended_rule.casbin_rule_key)

    def test_role_unassignment_with_extended_model(self):
        """Test role unassignment when ExtendedCasbinRule model is in use.

        Expected Results:
        - Role unassignment is successful (HTTP 207 Multi-Status).
        - The associated ExtendedCasbinRule is deleted.
        - No orphaned ExtendedCasbinRule remains after unassignment.
        """
        payload = {
            "users": [self.user.username],
            "role": self.role_key,
            "scope": str(self.library_key),
        }
        create_response = self.client.put(self.url, payload, format="json")
        self.assertEqual(create_response.status_code, status.HTTP_207_MULTI_STATUS)
        self.assertEqual(len(create_response.data["completed"]), 1)

        delete_params = {
            "role": self.role_key,
            "scope": str(self.library_key),
            "users": self.user.username,
        }
        unassign_response = self.client.delete(f"{self.url}?{urlencode(delete_params)}")

        self.assertEqual(unassign_response.status_code, status.HTTP_207_MULTI_STATUS)
        self.assertEqual(len(unassign_response.data["completed"]), 1)

        extended_rule = ExtendedCasbinRule.objects.filter(
            subject__usersubject__user=self.user,
            scope__contentlibraryscope__content_library=self.content_library,
        ).first()
        self.assertIsNone(extended_rule)

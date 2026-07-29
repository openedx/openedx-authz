"""Unit tests for the Course Authoring REST API view."""

from unittest.mock import patch

from django.urls import reverse
from rest_framework import status

from openedx_authz.tests.rest_api.test_views import ViewTestMixin


class TestWaffleFlagStatesAPIView(ViewTestMixin):
    """Test suite for WaffleFlagStatesAPIView."""

    def setUp(self):
        """Set up test fixtures."""
        super().setUp()
        self.url = reverse("openedx_authz:waffle-flag-states")

    def test_get_returns_the_waffle_flag_states(self):
        """Test GET /waffle-flag-states/ with a successful lookup.

        Expected result:
            - Returns 200 OK status.
            - The response body is whatever get_waffle_flag_states returns, unchanged.
        """
        flag_states = {
            "global": True,
            "org_overrides": {"on": ["Org1"], "off": []},
            "course_overrides": {"on": [], "off": ["course-v1:Org1+COURSE1+2024"]},
        }
        with patch(
            "openedx_authz.rest_api.v1.course_authoring.views.get_waffle_flag_states", return_value=flag_states
        ):
            response = self.client.get(self.url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data, flag_states)

    def test_get_handles_an_unexpected_error(self):
        """Test GET /waffle-flag-states/ when get_waffle_flag_states raises.

        Expected result:
            - Returns 500 INTERNAL SERVER ERROR status with a generic error message.
        """
        with patch(
            "openedx_authz.rest_api.v1.course_authoring.views.get_waffle_flag_states", side_effect=Exception("boom")
        ):
            response = self.client.get(self.url)

        self.assertEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)
        self.assertEqual(response.data, {"message": "error"})

    def test_get_requires_authentication(self):
        """Test GET /waffle-flag-states/ without authentication.

        Expected result:
            - Returns 401 UNAUTHORIZED status.
        """
        self.client.force_authenticate(user=None)

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

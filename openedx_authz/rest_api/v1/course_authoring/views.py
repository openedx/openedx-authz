"""
REST API view exposing Course Authoring data.

This is the one endpoint in openedx-authz whose data is not Authorization's own,
kept as a bounded, documented exception. See
``docs/decisions/0015-expose-course-authoring-waffle-flag-state-via-rest-api.rst``
and ``docs/decisions/0016-rest-api-domain-ownership-boundary.rst``.
"""

import logging

from django.http import HttpRequest
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from openedx_authz.rest_api.decorators import view_auth_classes
from openedx_authz.utils import get_waffle_flag_states

logger = logging.getLogger(__name__)


@view_auth_classes()
class WaffleFlagStatesAPIView(APIView):
    """
    Simple API view that returns the waffle flag states from utils.get_waffle_flag_states.

    **Endpoints**

    - GET: Retrieve the enablement state of the course-authoring waffle flag across different scopes.

    **Response Format**

    * 'global' (bool): True if the global waffle flag is enabled.
    * 'org_overrides' (dict): Orgs with an organization-level override, as 'on'
      (forces the flag on) and 'off' (forces the flag off) lists.
    * 'course_overrides' (dict): Courses with a course-level override, split the same way.

    **Example Request**

    GET /api/authz/v1/waffle-flag-states/
    """

    def get(self, request: HttpRequest) -> Response:
        """Retrieve the enablement state of the course-authoring waffle flag across different scopes."""
        try:
            data = get_waffle_flag_states()
            return Response(data, status=status.HTTP_200_OK)
        except Exception as e:      # pylint: disable=broad-exception-caught
            logger.exception("Error getting waffle flag states: %s", e)
            return Response({"message": "error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

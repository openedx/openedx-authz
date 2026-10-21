"""Compatibility exports for built-in permission constants."""

# pylint: disable=wildcard-import,unused-wildcard-import

from openedx_authz.applets.content_libraries import constants as content_libraries
from openedx_authz.applets.content_libraries.constants import *  # noqa: F403
from openedx_authz.applets.course_authoring import constants as course_authoring
from openedx_authz.applets.course_authoring.constants import *  # noqa: F403
from openedx_authz.applets.course_team_roles import constants as course_team_roles
from openedx_authz.applets.course_team_roles.constants import *  # noqa: F403

__all__ = [
    *content_libraries.__all__,
    *course_authoring.__all__,
    *course_team_roles.__all__,
]

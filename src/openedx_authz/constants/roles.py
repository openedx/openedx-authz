"""Compatibility exports for built-in role constants."""

# pylint: disable=wildcard-import,unused-wildcard-import

from openedx_authz.applets.content_libraries import roles as content_libraries
from openedx_authz.applets.content_libraries.roles import *  # noqa: F403
from openedx_authz.applets.course_team_roles import roles as course_team_roles
from openedx_authz.applets.course_team_roles.roles import *  # noqa: F403

__all__ = [
    *content_libraries.__all__,
    *course_team_roles.__all__,
]

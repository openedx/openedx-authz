"""Compatibility exports for built-in role constants."""

from openedx_authz.applets.content_libraries.constants import (
    LIBRARY_ADMIN,
    LIBRARY_AUTHOR,
    LIBRARY_CONTRIBUTOR,
    LIBRARY_USER,
)
from openedx_authz.applets.course_team_roles.constants import (
    CCX_COACH,
    COURSE_ADMIN,
    COURSE_AUDITOR,
    COURSE_BETA_TESTER,
    COURSE_DATA_RESEARCHER,
    COURSE_EDITOR,
    COURSE_LIMITED_STAFF,
    COURSE_STAFF,
    LEGACY_COURSE_ROLE_EQUIVALENCES,
)

__all__ = [
    "CCX_COACH",
    "COURSE_ADMIN",
    "COURSE_AUDITOR",
    "COURSE_BETA_TESTER",
    "COURSE_DATA_RESEARCHER",
    "COURSE_EDITOR",
    "COURSE_LIMITED_STAFF",
    "COURSE_STAFF",
    "LEGACY_COURSE_ROLE_EQUIVALENCES",
    "LIBRARY_ADMIN",
    "LIBRARY_AUTHOR",
    "LIBRARY_CONTRIBUTOR",
    "LIBRARY_USER",
]

"""
Course-team role constants.

Each constant identifies a role. Its permissions are defined in the applets' YAML schema files.
"""

from openedx_authz.api.data import RoleData
from openedx_authz.applets.course_team_roles.constants import (
    COURSE_ADMIN_ID,
    COURSE_AUDITOR_ID,
    COURSE_BETA_TESTER_ID,
    COURSE_DATA_RESEARCHER_ID,
    COURSE_EDITOR_ID,
    COURSE_LIMITED_STAFF_ID,
    COURSE_STAFF_ID,
)

COURSE_AUDITOR = RoleData(external_key=COURSE_AUDITOR_ID)
COURSE_EDITOR = RoleData(external_key=COURSE_EDITOR_ID)
COURSE_ADMIN = RoleData(external_key=COURSE_ADMIN_ID)
COURSE_STAFF = RoleData(external_key=COURSE_STAFF_ID)
COURSE_LIMITED_STAFF = RoleData(external_key=COURSE_LIMITED_STAFF_ID)
COURSE_DATA_RESEARCHER = RoleData(external_key=COURSE_DATA_RESEARCHER_ID)
COURSE_BETA_TESTER = RoleData(external_key=COURSE_BETA_TESTER_ID)

# This is a known LMS-only permission, but doesn't actually grant anything yet.
#
# It is intended to be handled in the Willow time frame.
CCX_COACH = RoleData(external_key="ccx_coach")


# Map of legacy course role names to their equivalent new roles
# This mapping must be unique in both directions, since it may be used as a reverse lookup (value → key).
# If multiple keys share the same value, it will lead to collisions.
LEGACY_COURSE_ROLE_EQUIVALENCES = {
    "instructor": COURSE_ADMIN.external_key,
    "staff": COURSE_STAFF.external_key,
    "limited_staff": COURSE_LIMITED_STAFF.external_key,
    "data_researcher": COURSE_DATA_RESEARCHER.external_key,
    "beta_testers": COURSE_BETA_TESTER.external_key,
    "ccx_coach": CCX_COACH.external_key,
}

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
]

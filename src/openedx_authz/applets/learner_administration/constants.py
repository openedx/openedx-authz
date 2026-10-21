"""Learner Administration permission constants."""

from openedx_authz.data import ActionData, PermissionData

__all__ = [
    "COURSES_VIEW_COURSE_INFO",
    "COURSES_VIEW_LEARNER_EXTENSIONS",
    "COURSES_MANAGE_LEARNER_EXTENSIONS",
    "COURSES_VIEW_COHORTS",
    "COURSES_MANAGE_COHORTS",
]

COURSES_NAMESPACE = "courses"

COURSES_VIEW_COURSE_INFO = PermissionData(
    action=ActionData(external_key=f"{COURSES_NAMESPACE}.view_course_info"),
    effect="allow",
)

COURSES_VIEW_LEARNER_EXTENSIONS = PermissionData(
    action=ActionData(external_key=f"{COURSES_NAMESPACE}.view_learner_extensions"),
    effect="allow",
)

COURSES_MANAGE_LEARNER_EXTENSIONS = PermissionData(
    action=ActionData(external_key=f"{COURSES_NAMESPACE}.manage_learner_extensions"),
    effect="allow",
)

COURSES_VIEW_COHORTS = PermissionData(
    action=ActionData(external_key=f"{COURSES_NAMESPACE}.view_cohorts"),
    effect="allow",
)

COURSES_MANAGE_COHORTS = PermissionData(
    action=ActionData(external_key=f"{COURSES_NAMESPACE}.manage_cohorts"),
    effect="allow",
)

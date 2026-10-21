"""Enrollments permission constants."""

from openedx_authz.data import ActionData, PermissionData

__all__ = [
    "COURSES_VIEW_ENROLLMENTS",
    "COURSES_ENROLL_LEARNERS",
    "COURSES_UNENROLL_LEARNERS",
]

COURSES_NAMESPACE = "courses"

COURSES_VIEW_ENROLLMENTS = PermissionData(
    action=ActionData(external_key=f"{COURSES_NAMESPACE}.view_enrollments"),
    effect="allow",
)

COURSES_ENROLL_LEARNERS = PermissionData(
    action=ActionData(external_key=f"{COURSES_NAMESPACE}.enroll_learners"),
    effect="allow",
)

COURSES_UNENROLL_LEARNERS = PermissionData(
    action=ActionData(external_key=f"{COURSES_NAMESPACE}.unenroll_learners"),
    effect="allow",
)

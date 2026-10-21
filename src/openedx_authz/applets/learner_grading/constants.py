"""Learner Grading permission constants."""

from openedx_authz.data import ActionData, PermissionData

__all__ = [
    "COURSES_VIEW_GRADEBOOK",
    "COURSES_MANAGE_LEARNER_GRADING",
]

COURSES_NAMESPACE = "courses"

COURSES_VIEW_GRADEBOOK = PermissionData(
    action=ActionData(external_key=f"{COURSES_NAMESPACE}.view_gradebook"),
    effect="allow",
)

COURSES_MANAGE_LEARNER_GRADING = PermissionData(
    action=ActionData(external_key=f"{COURSES_NAMESPACE}.manage_learner_grading"),
    effect="allow",
)

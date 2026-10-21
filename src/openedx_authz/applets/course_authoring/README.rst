Course Authoring
################

This applet owns the existing built-in permissions for authoring, configuring,
and managing the team of a course. It adds those permissions to the shared
course-team roles through role extensions, while the role identifiers and
metadata remain in ``course_team_roles``.

The applet is an internal package. Existing consumers should continue importing
permission and role constants from ``openedx_authz.constants``.

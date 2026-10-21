Course Authoring
################

This applet owns the existing built-in permissions for authoring, configuring, and managing the team of a course. It adds those permissions to the shared course-team roles through role extensions, while the role identifiers and metadata remain in ``course_team_roles``. ``constants.py`` contains its permission objects.

The applet is an internal package, so clients import these constants from ``openedx_authz.constants.permissions``, which re-exports the objects defined here.

Course-Team Roles
#################

This applet owns the identifiers and metadata for roles held by members of a course team, including the legacy compatibility roles. Their base definitions list only the legacy compatibility permissions, and the applets that own every other permission add it through role extensions.

The legacy compatibility permissions also live here because they connect these roles to the previous course-role system. ``constants.py`` contains these permission objects, and ``roles.py`` contains the role constants, which identify each role without listing its permissions.

The applet is an internal package, so clients import these constants from ``openedx_authz.constants.permissions`` and ``openedx_authz.constants.roles``, which re-export the objects defined here.

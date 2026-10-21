Course-Team Roles
#################

This applet owns the identifiers and metadata for roles held by members of a course team, including the legacy compatibility roles. Their base definitions have empty permission lists because the applets that own each permission add it through role extensions.

The legacy compatibility permissions also live here because they connect these roles to the previous course-role system. ``roles.py`` contains the role constants, which identify each role without listing its permissions. Existing consumers continue importing them from ``openedx_authz.constants``.

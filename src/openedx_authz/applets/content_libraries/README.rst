Content Libraries
#################

This applet owns the built-in roles and permissions for Content Libraries. Its
``schema`` directory is loaded through the package's existing ``authz.schema``
entry point, while ``constants.py`` contains its permission objects and
``roles.py`` contains its role objects.

The applet is an internal package. Existing consumers should continue importing
Library constants from ``openedx_authz.constants.permissions`` and
``openedx_authz.constants.roles``, which re-export the objects defined here.

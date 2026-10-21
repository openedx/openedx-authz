Learner Administration
######################

This applet owns the permissions for viewing course information and managing learner extensions and cohorts, which belong to the Support Learning bounded context. It adds those permissions to the ``course_admin`` and ``course_staff`` roles through role extensions. ``constants.py`` contains its permission objects.

The applet is an internal package, so clients import these constants from ``openedx_authz.constants.permissions``, which re-exports the objects defined here.

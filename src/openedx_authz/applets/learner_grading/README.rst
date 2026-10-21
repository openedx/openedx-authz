Learner Grading
###############

This applet owns the permissions for viewing the gradebook and using grading tools for individual learners, which belong to the Consuming Learning Content bounded context. It adds those permissions to the ``course_admin`` and ``course_staff`` roles through role extensions. ``constants.py`` contains its permission objects.

The applet is an internal package, so clients import these constants from ``openedx_authz.constants.permissions``, which re-exports the objects defined here.

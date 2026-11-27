Learner Grading
###############

This applet owns the permissions for viewing the gradebook and using grading tools for individual learners or all learners, which belong to the Consuming Learning Content bounded context. It adds those permissions to the ``course_admin`` and ``course_staff`` roles through role extensions. It also adds the ones matching the legacy limited staff access to the hidden ``course_limited_staff`` role. ``constants.py`` contains its permission objects.

The applet is an internal package, so clients import these constants from ``openedx_authz.authz``. The existing ``openedx_authz.constants.permissions`` path remains a compatibility export.

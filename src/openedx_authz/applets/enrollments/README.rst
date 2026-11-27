Enrollments
###########

This applet owns the permissions for viewing course enrollments and for enrolling or unenrolling learners, which belong to the Content Access / Enrollments bounded context. It adds those permissions to the ``course_admin`` and ``course_staff`` roles through role extensions. It also adds them to the hidden ``course_limited_staff`` role. ``constants.py`` contains its permission objects.

The applet is an internal package, so clients import these constants from ``openedx_authz.authz``. The existing ``openedx_authz.constants.permissions`` path remains a compatibility export.

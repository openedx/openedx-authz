Built-In Python Constants
#########################

Applications import built-in permission and role constants from ``openedx_authz.authz``:

.. code-block:: python

   from openedx_authz.authz import COURSE_ADMIN, COURSES_VIEW_COURSE

Each applet keeps the permission and role constants it owns in one ``constants.py`` file. The YAML schema remains the source of truth for role composition, so role constants identify roles without copying their complete permission lists.

``openedx_authz.constants.permissions`` and ``openedx_authz.constants.roles`` remain available as compatibility imports. New code should use ``openedx_authz.authz``.


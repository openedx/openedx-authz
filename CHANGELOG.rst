Change Log
##########

..
   All enhancements and patches to openedx_authz will be documented
   in this file.  It adheres to the structure of https://keepachangelog.com/ ,
   but in reStructuredText instead of Markdown (for ease of incorporation into
   Sphinx documentation and the PyPI description).

   This project adheres to Semantic Versioning (https://semver.org/).

.. There should always be an "Unreleased" section for changes pending release.

Unreleased
**********

*

0.4.0 - 2025-16-10
******************

Changed
=======

* Initialize enforcer when application is ready to avoid access errors.

0.3.0 - 2025-10-10
******************

Added
=====

* Implementation of REST API for roles and permissions management.

0.2.0 - 2025-10-10
******************

Added
=====

* ADRs for key design decisions.
* Casbin model (CONF) and engine layer for authorization.
* Implementation of public API for roles and permissions management.

0.1.0 - 2025-08-27
******************

Added
=====

* Basic repo structure and initial setup.

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

0.10.1 - 2025-10-28
********************

Fixed
=====

* Fix constants and test class to be able to use it outside this app.

0.10.0 - 2025-10-28
*******************

Added
=====

* New ``get_object()`` method in ScopeData to retrieve underlying domain objects
* Implementation of ``get_object()`` for ContentLibraryData with canonical key validation

Changed
=======

* Refactor ``ContentLibraryData.exists()`` to use ``get_object()`` internally

0.9.1 - 2025-10-28
******************

Fixed
=====

* Fix role user count to accurately filter users assigned to roles within specific scopes instead of across all scopes.

0.9.0 - 2025-10-27
******************

Added
=====

* Function API to retrieve scopes for a given role and subject.

0.8.0 - 2025-10-24
******************

Added
=====

* Allow disabling auto-load and auto-save of policies by setting CASBIN_AUTO_LOAD_POLICY_INTERVAL to -1.

Changed
=======

* Migrate from using pycodestyle and isort to ruff for code quality checks and formatting.
* Enhance enforcement command with dual operational modes (database and file mode).

0.7.0 - 2025-10-23
******************

Added
=====

* Initial migration to establish dependency on casbin_adapter for automatic CasbinRule table creation.

0.6.0 - 2025-10-22
******************

Changed
=======

* Use a SyncedEnforcer with default auto load policy.

Removed
=======

* Remove Casbin Redis watcher from engine configuration.

0.5.0 - 2025-10-21
******************

Added
=====

* Default policy for Content Library roles and permissions.

Fixed
=====

* Add plugin_settings in test settings.
* Update permissions for RoleListView.

0.4.1 - 2025-10-16
******************

Fixed
=====

* Load policy before adding policies in the loading script to avoid duplicates.

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

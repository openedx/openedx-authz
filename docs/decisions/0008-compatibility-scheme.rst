0008: Compatibility scheme with the current system
###################################################

Status
******

**Draft** *2025-09-29*

Context
*******

Open edX has its authorization system described in the `OEP-66`_, but due to its limitations, the community wanted to explore a more appropriate option for managing authorization on the platform. To mitigate the possible risk associated with completely overhauling a core system like authorization, our primary strategy is to implement a staging or phased migration plan. This approach enables us to limit the blast radius to test components in a controlled environment, apply lessons learned, and ensure business continuity, thereby giving users time to adapt.

Decision
********

* The new authorization will coexist with the previous one until we migrate the entire system.
* We will start migrating the current library permissions and roles to the new authorization system.
    * For the MVP, we will maintain the current functionality using the new architecture.

Consequences
************

Migration Strategy for Libraries
=================================

* Develop a migration script to transform the existing explicit role assignments to the new authorization model, without modifying the previous table.
* We will modify the enforcement points related to library permissions in the new system and verify other enforcement points, which will be updated with the latest set of `Roles and Permissions for Libraries`_.
* We will use the authorization API system for the libraries' endpoints related to authorization. Example: Obtaining the list of users who have permissions over a scope.
* Create a deprecation ticket to let the community know how the library roles and permissions will work.
* Update the `OEP-66`_ doc regarding the library's new authorization system.

For more information regarding the API and communication, see the `Enforcement mechanisms ADR`_.

For more information on how the existing roles and permissions of libraries will be translated, see the `Libraries Roles and Permissions Migration Plan`_ document.

Rejected Alternatives
*********************

* Change the authorization system completely at once.
* Utilize the existing tables and mechanisms to enforce permissions within the new system.
* Use library-specific API endpoints regarding authorization.

References
**********

* `OEP-66`_
* `Roles and Permissions for Libraries`_
* `Enforcement mechanisms ADR`_
* `Libraries Roles and Permissions Migration Plan`_

.. _OEP-66: https://docs.openedx.org/projects/openedx-proposals/en/latest/best-practices/oep-0066-bp-authorization.html

.. _Roles and Permissions for Libraries: https://openedx.atlassian.net/wiki/spaces/OEPM/pages/4840095745/Library+Roles+and+Permissions

.. _Enforcement mechanisms ADR: https://github.com/openedx/openedx-authz/blob/main/docs/decisions/0007-enforcement-mechanisms-mfe.rst

.. _Libraries Roles and Permissions Migration Plan: https://openedx.atlassian.net/wiki/spaces/OEPM/pages/5252317270/Libraries+Roles+and+Permissions+Migration+Plan

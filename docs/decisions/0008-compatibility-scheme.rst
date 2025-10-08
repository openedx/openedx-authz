0008: Compatibility scheme with the current system
###################################################

Status
******

**Draft** *2025-09-29*

Context
*******

Open edX has its authorization system described in the `OEP-66`_, but due to its limitations, the community wanted to explore a more appropriate option for managing authorization on the platform. To mitigate the possible risk associated with completely overhauling a core system like authorization, our primary strategy is to implement a phased migration plan. This approach enables us to limit the blast radius to test components in a controlled environment, apply lessons learned, and ensure business continuity, thereby giving users time to adapt.

Decision
********

* The new authorization system, defined in this repository, will coexist with the previous one (described in the `OEP-66`_) until we migrate the entire system.
* We will start migrating the current library permissions and roles to the new authorization system.
    * For the MVP, we will maintain the current functionality using the new architecture.

Consequences
************

Immediate System Impact
========================

* **Increased System Complexity:** The platform will temporarily operate with two active authorization models.
* **Data Duplication:** Permission data will exist in both the legacy and new systems until the final cutover, requiring sync mechanisms or specific query logic.
* **API Utilization:**  We will use the new authorization API for the authorization related methods. (See the `Enforcement mechanisms ADR`_ for details.)

Phased Migration Approach
==========================

Migration Strategy for Libraries
---------------------------------

This phase focuses on migrating library permissions while maintaining current functionality using the new architecture.

* **Migration Script:** Develop a script to transform existing explicit role assignments into the new authorization model without modifying the legacy database.
* **Enforcement Updates:** Modify and verify enforcement points related to library permissions to use the new system and the latest `Roles and Permissions for Libraries`_.
* **Documentation and Communication:**
    * Create a deprecation ticket to inform the community about changes to library roles and permissions.
    * Update the `OEP-66`_ document regarding the library's new authorization system.

For detailed role translation, see the `Libraries Roles and Permissions Migration Plan`_ document.

Subsequent Migrations (General Steps)
-------------------------------------

Once the Libraries work is complete, subsequent components will be moved to the new system. Lessons learned from the Libraries implementation will inform the adoption plan, but each new area will require the following general steps:

#.  **Investigation:** Document existing permissions, roles, and how they are currently stored.
#.  **Model Validation:** Ensure the new authorization model handles all existing use cases, adapting the model or use cases as necessary.
#.  **Enforcement Replacement:** Replace existing authorization checks with checks against the new system, including updating relevant API calls and deprecating/creating new API endpoints as required.
#.  **Migration Script:** Write and thoroughly test a migration script that moves existing permissions to the new system without modifying or removing old data.
#.  **Testing:** Thoroughly test the migration script, new checks, and endpoints to ensure functional parity.


Rejected Alternatives
*********************

* Change the authorization system completely at once.
* Utilize the existing tables and mechanisms to enforce permissions within the new system.
* Use component-specific API endpoints for authorization queries.

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

0004: Authorization Technology Selection
#########################################

Status
******

**Accepted** *2025-09-22*

Context
*******

Authorization is a common challenge across software platforms, and many open-source communities have already built frameworks to address it. To understand what could work for Open edX, we reviewed a range of existing technologies and compared them against `a consistent set of evaluation criteria`_, to:

* Avoid reinventing the wheel by leveraging proven approaches.
* Learn from established patterns (RBAC, ABAC, ReBAC, policy-based models).
* Choose solutions that balance flexibility with maintainability.
* Ensure long-term scalability and alignment with modern best practices.

We analyzed a variety of authorization technologies, including Django permissions, Django-guardian, Django-prbac, Bridgekeeper, Edx-rbac, Casbin, Spicedb, Keycloak, Cerbos/Permguard. The complete analysis of these solutions can be found here: `Authorization Technologies Reviewed`_.

Following this preliminary assessment, we determined that Django-prbac, Casbin, and OpenFGA were the solutions most closely aligned with the requirements. We create a comparison table to decide which one is more suitable for our use case, taking into account factors such as integration fit, permission management, performance, extensibility, maturity, security, learning curve, total cost of operations, and other relevant considerations. Here you can find the `Authorization Technologies Comparison Table`_.

Decision
********

* We choose to use `Casbin`_ as the authorization engine for Open edX, which allows us to have a robust foundation, enabling long-term evolution; improves security because it enforce the principle of least privilege; help us maintain a centrilize logic, making it easier to manage and update; and promotes best practice because has support for multiple well-understood authorization models. This decision of using Casbin is also aligned with the `Authorization Model Foundations ADR`_.

* We will integrate Casbin as a library (using the production-ready Python library, `PyCasbin`_) within our services to avoid introducing a new service.

* We'll use a centralized policy enforcement, which means all access requests are evaluated against a unified set of policies before granting or denying access.

Consequences
************

* Additional Layer: An abstraction layer will need to be created to shield stakeholders (including Open edX services) from the complexities of direct Casbin policy management (with APIs, enforcement utilities, etc).

* Casbin as a default dependency: Casbin will be included as a default dependency in our services, ensuring that it is available for authorization tasks.

* Performance considerations: We need to consider how policy loading, matching, and enforcement affect the overall performance.

* Data consistency: Watchers and robust strategies are required to ensure that the authorization policies are consistent across different services.


Rejected Alternatives
*********************

Permission-centric approach
============================

* Strengths: This approach is simple and easy to understand for basic use cases and static permissions.

* Limitations: Managing thousands of individual permissions is not scalable and can lead to unmanageable complexity and security vulnerabilities.


Policy Decision Points (PDPs) like Cerbos and Permguard
========================================================

* Model: Stateless Policy Decision Points (PDPs). Evaluate requests against policies (YAML/JSON) and return allow/deny.

* Strengths: Clean separation of logic; ABAC-friendly; flexible deployment modes (service, sidecar, embedded).

* Limitations: Do not manage users or roles; must be combined with another system.


Django-prbac
==============

* Model: Built around Role and Grant, it creates a graph of roles connected by privileges. Role definitions can be parameterized (e.g., by organization or course), enabling scoped RBAC and a limited form of ABAC.

* Strengths: Native to Django, intuitive for developers familiar with Django patterns, and simple to use.

* Limitations: Incomplete query/filtering layer, and centralization remains within each service.


ReBAC Solutions (SpiceDB, OpenFGA)
===================================

* Model: These are centralized, Zanzibar-inspired systems that model permissions as a graph of relationships (ReBAC). They are designed to run as a dedicated, standalone service that the application connects to.

* Strengths: Both are highly powerful and expressive, built for large-scale, complex relationship-based access control. They are battle-tested technologies with strong open-source support.

* Limitations: These solutions were considered overly complex for our current needs, which RBAC and ABAC primarily meet. Running a separate service introduces significant operational overhead and a steeper learning curve.


References
**********

* `Authorization Model Foundations ADR`_
* `Authorization Technologies Reviewed`_
* `Authorization Technologies Comparison Table`_
* `Casbin`_
* `PyCasbin`_


.. _a consistent set of evaluation criteria: https://openedx.atlassian.net/wiki/spaces/OEPM/pages/5179179033/AuthZ+Technologies+Comparison#Framework-for-Evaluation

.. _Authorization Model Foundations ADR: https://github.com/openedx/openedx-authz/blob/main/docs/decisions/0002-authorization-model-foundation.rst

.. _Authorization Technologies Comparison Table: https://openedx.atlassian.net/wiki/spaces/OEPM/pages/5179179033/AuthZ+Technologies+Comparison#Comparison-Table

.. _Authorization Technologies Reviewed: https://openedx.atlassian.net/wiki/spaces/OEPM/pages/5179179033/AuthZ+Technologies+Comparison#Authorization-Technologies-Reviewed

.. _Casbin: https://casbin.org/

.. _PyCasbin: https://github.com/casbin/pycasbin

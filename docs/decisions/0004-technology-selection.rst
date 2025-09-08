0004: Authorization Technology Selection
#########################################

Status
******

**Draft** *2025-09-12*

Context
*******

Authorization is a common challenge across software platforms, and many open-source communities have already built frameworks to address it (e.g., Casbin, Cerbos, OpenFGA, SpiceDB, django-guardian). To understand what could work for Open edX, we reviewed a range of existing technologies and compared them against `a consistent set of evaluation criteria`_, to:

* Avoid reinventing the wheel by leveraging proven approaches.
* Learn from established patterns (RBAC, ABAC, ReBAC, policy-based models).
* Choose solutions that balance flexibility with maintainability.
* Ensure long-term scalability and alignment with modern best practices.


Decision
********

Policy-based over a Permission-centric approach
==================================================

A policy-based approach is a method of managing resource access by defining rules and conditions rather than making direct, specific assignments. It's about setting general guidelines that are enforced automatically.

We are choosing policy-based over permission-centric because the first one has improvements in the following areas:

* Flexibility and Granularity: It allows for more specific and detailed access rules based on context and attributes, rather than just on a user's identity.

* Scalability: It's easier to manage access in large, complex systems. Instead of assigning individual permissions to thousands of users, you manage a smaller number of policies.

* Dynamic Access: Access decisions are made in real-time based on current conditions (e.g., time of day, location, resource), making it more adaptable to changing needs.

* Improved Security: It enforces the principle of least privilege more effectively, as access is only granted when all conditions are met, reducing the risk of over-provisioning permissions.

* Centralized Management: Policies can be centrally defined and updated, and the changes are automatically applied across the system without manual intervention for each user.

In this approach, you use policies to make decisions. A policy is a statement that defines "who (subject) can do what(action), to which resource(resource), under what conditions (context)."

Also, this decision is supported by decisions in the `Authorization Model Foundations ADR`_.


Casbin as a technology to implement the AuthZ system
=====================================================

Based on a broad initial study, we analyzed a variety of authorization technologies, including Django permissions, django-guardian, django-prbac, bridgekeeper, edx-rbac, casbin, spicedb, keycloak, cerbos/permguard. The complete analysis of these solutions, and the rationale for the initial findings, can be found here: `Authorization Technologies Reviewed`_.

Following this preliminary assessment, we determined that django-prbac, Casbin, and OpenFGA were the solutions most closely aligned with the requirements. These three candidates were then subjected to a more in-depth evaluation against a comprehensive set of criteria. The assessment focused on key factors, including Role and Permission Management, Integration Fit, and Extensibility, as well as an analysis of Maturity, Community Support, and Total Cost of Ownership.

After a thorough review, Casbin was selected as the technology we'll use due to its superior performance across all evaluation criteria. For a complete breakdown of the evaluation, including a detailed explanation of the requirements and the specific scores for each technology, please visit `AuthZ Technologies Comparison`_.


Consequences
************

Benefits of this decision
=========================

The adoption of a policy-based model with Casbin provides some advantages:

* Builds a Robust Foundation: This model provides a solid basis for future authorization needs, allowing for more complex rules (like ABAC) without changing the application's code.

* Improves Security: It effectively enforces the principle of least privilege, which helps reduce the risk of over-provisioning permissions.

* Centralizes Logic: Authorization logic is easier to manage and update because rules are defined in a single place.

* Promotes Best Practices: Support for multiple, well-understood authorization models (such as RBAC and ABAC) promotes the use of established patterns and best practices.


Potential Drawbacks
=====================

Despite its benefits, this decision does come with some trade-offs:

* Higher Learning Curve: The community will face a higher initial learning curve compared to using a built-in Django-based solution.

* Migration Effort: A dedicated effort is required to migrate any existing authorization logic to the new policy framework.

* Additional Layer: An abstraction layer will need to be created to shield stakeholders from the complexities of direct Casbin policy management.


Rejected Alternatives
*********************

Permission-centric approach
============================

* Strengths: This approach is simple and easy to understand for basic use cases and static permissions.

* Limitations: It becomes unmanageable as access requirements become more complex, especially with dynamic or contextual logic. Managing thousands of individual permissions is not scalable and can lead to unmanageable complexity and security vulnerabilities.


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

.. (Optional) List any additional references here that would be useful to the future reader. See `Documenting Architecture Decisions`_ for further input.

.. _a consistent set of evaluation criteria: https://openedx.atlassian.net/wiki/spaces/OEPM/pages/5179179033/AuthZ+Technologies+Comparison#Framework-for-Evaluation

.. _Authorization Model Foundations ADR: https://github.com/openedx/openedx-authz/blob/main/docs/decisions/0002-authorization-model-foundation.rst

.. _AuthZ Technologies Comparison: https://openedx.atlassian.net/wiki/x/GQC0NAE

.. _Authorization Technologies Reviewed: https://openedx.atlassian.net/wiki/spaces/OEPM/pages/5179179033/AuthZ+Technologies+Comparison#Authorization-Technologies-Reviewed

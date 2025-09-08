0001: Purpose of This Repo
##########################

Status
******

**Draft**

Context
*******

The authorization (AuthZ) project is a community initiative to modernize how roles and permissions are defined, stored, and evaluated across the ecosystem. The existing system is fragmented, inflexible, and often results in over-permissioned users, repetitive administrative tasks, and difficulty adapting roles to organizational needs.

This project aims to introduce a unified authorization model that supports custom roles, flexible scopes, and policy-based evaluation. By decoupling role/permission logic from application code, the goal is to achieve a more scalable, extensible, and user-friendly authorization framework.

For more details, please refer to the `Roles & Permissions confluence space <https://openedx.atlassian.net/wiki/spaces/OEPM/pages/4724490259>`_.

Decision
********

We will create a repository to hold the architecture, design decisions, and reference implementation for the Open edX Authorization (AuthZ) project.

This repository will serve as the central place for:

- Architectural Decision Records (ADRs) that document the evolution of the authorization model.
- Design documents for scopes, policies, and integration approaches.
- Implementation of the new authorization framework which will eventually replace the legacy authorization system.
- Utilities which will be imported by other services in the Open edX ecosystem to leverage the new authorization capabilities.
- Migration strategies for replacing legacy RBAC models with this new system.

Consequences
************

- This repository will provide a single source of truth for all architectural and design decisions regarding the new authorization framework.
- It will make it easier to share progress, collect feedback, and collaborate across the community.
- It decouples AuthZ development from ``edx-platform``, ensuring that the project can evolve independently and be later a reusable Django library.
- The repo creates a clear boundary for experimentation and iteration, while providing a migration path to replace legacy role/permission handling over time.

Rejected Alternatives
*********************

- **Using the edx-platform repository for AuthZ work.**
  - Keeping the new authorization work inside ``edx-platform`` would limit flexibility, slow down iteration, and tightly couple experimental design with production code.
  - A standalone repo enables a cleaner separation of concerns and aligns with the long-term goal of the authorization framework to be leveraged across different services in the Open edX ecosystem.

References
**********

- Technical Approach: `AuthZ <https://openedx.atlassian.net/wiki/spaces/OEPM/pages/5176229910>`_
- PRD: `Roles & Permissions <https://openedx.atlassian.net/wiki/spaces/OEPM/pages/4724490259>`_
- OEP-66: :ref:`Authorization Best Practices <openedx-proposals:OEP-66 User Authorization>`

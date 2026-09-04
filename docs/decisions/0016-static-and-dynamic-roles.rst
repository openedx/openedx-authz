0016: Keep Static and Dynamic Roles Separate
############################################

Status
******

**Draft**

Context
*******

Open edX needs two kinds of roles: static roles defined by applications and dynamic roles created through the application. Users work with both kinds through the same interface.

Today, the system derives available roles and permissions from Casbin policy rows loaded during deployment, which means that it supports only static roles.

Decision
********

Static and dynamic definitions
==============================

Applications, such as Django apps or IDAs, define static roles in the Open edX Authorization schema, or authz schema for short (defined in more detail in `ADR 0017`_). Because the application owns these roles, changes to them are made in the schema and released with the application.

Dynamic roles are created through the application, and the authz model stores both their definitions and their user assignments. Static definitions remain in the authz schema.

For example, an application may define ``course_admin`` in the authz schema, while a user creates ``course_reviewer`` through the application. The authz model stores ``course_reviewer``, but ``course_admin`` remains part of the application's schema.

This ADR does not decide who can create or change roles. Static role changes require a deployment, so they need site operator access. Dynamic roles may be managed through Django admin or a similar interface, but we have not decided who will have that access. A site operator and an application administrator have different responsibilities, although the same person may be both.

Consequences
************

* Dynamic roles can be created without changing or redeploying applications.
* Static and dynamic roles can change independently.
* The authz model must store dynamic role definitions.

.. _ADR 0017: 0017-static-authorization-schema.rst

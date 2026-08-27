0022: Defer Permission Implication and Role Inheritance
#######################################################

Status
******

**Draft**

Context
*******

Permission categories group definitions for display, whereas permission implication and role inheritance change the role-permission assignments used for access checks. Casbin can represent these relationships, but the current use cases work by listing every permission directly on each static role. Adding implication or inheritance now would therefore require rules for cycles, conflicting allow and deny effects, scope compatibility, API presentation, testing, and overrides before there is a use case that needs them.

Decision
********

#. First schema version
=======================

The first authz schema version supports explicit role-permission assignments, so every role lists each assigned permission.

For example, a role that needs both ``courses.manage_course_team`` and ``courses.view_course_team`` lists both permission IDs. The compiler does not infer that one permission includes the other.

#. Requirements for a later version
===================================

A later schema version may add implications or inheritance, but documents written for version 1 will keep their current meaning. Before introducing either feature, the new version must define:

* the schema syntax and Casbin representation;
* scope compatibility;
* cycle and missing-reference validation;
* the interaction between allow and deny effects;
* conflict and override behavior across applications;
* how APIs show direct and implied permissions; and
* tests that prove the resulting authorization decisions.

Until then, the current policy loader remains responsible for existing Casbin grouping rows.

Consequences
************

* The first compiler reads the permissions listed on each role.
* Schema files may repeat a permission across related roles.
* A role's API response lists its explicit permissions.
* The current policy loader continues to handle existing Casbin grouping rows.
* Introducing implication later requires a schema-version change and migration guidance.

Rejected Alternatives
*********************

Expose inheritance syntax without implementing it
=================================================

Unimplemented syntax would tell schema authors that a relationship exists without granting the corresponding access.

Implement implication in the first version
==========================================

The current extensibility use cases work with explicit role-permission assignments. Adding graph semantics would expand the first implementation and its security review before there is an agreed use case.

References
**********

* `ADR 0017`_

.. _ADR 0017: 0017-static-authorization-schema.rst

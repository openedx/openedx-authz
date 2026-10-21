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

1. First schema version
=======================

`ADR 0017`_ defines the first authz schema version with explicit role-permission assignments, so every role lists each assigned permission. This ADR records why permission implication and role inheritance remain outside that version.

For example, a role that needs both ``courses.manage_course_team`` and ``courses.view_course_team`` lists both permission IDs. The compiler does not infer that one permission includes the other.

2. Requirements for a later version
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

Addendum: Remove Existing Action Grouping (2026-10-16)
======================================================

The built-in roles list every permission covered by the existing ``g2`` action-grouping rows, so those rows do not change their effective permissions. The Casbin model now uses exact action matches and a data migration removes stored ``g2`` rows.

Permission grouping and role inheritance remain future work in `Issue #91`_ and `Issue #523`_. Any later implementation still requires the schema-version change and migration guidance described in this ADR.

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
* `Issue #91`_
* `Issue #523`_

.. _ADR 0017: 0017-static-authorization-schema.rst
.. _Issue #91: https://github.com/openedx/openedx-authz/issues/91
.. _Issue #523: https://github.com/openedx/openedx-authz/issues/523

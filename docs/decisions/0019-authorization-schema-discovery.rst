0019: Discover and Load Authorization Schemas During Deployment
###############################################################

Status
******

**Draft**

Context
*******

Applications, such as Django apps or IDAs, need a standard way to provide their static authz schema files. Because Open edX supports several deployment methods, discovery must work with Tutor, native deployments and local development.

Decision
********

1. Python entry point and package resources
===========================================

An application contributes one or more authz schema resources through a Python entry point defined by ``openedx-authz``. Discovery resolves those resources with the available mechanisms (like we discover Django applications or using ``importlib.resources``) and returns all contributions in a defined order, since package discovery order may vary.

For example, the ``course_authoring`` package can register ``course_authoring.authz:get_schema_resources`` under an entry-point group such as ``authz.schema``. The compiler loads that group to discover ``authz/course_authoring.authz.yaml`` and the schema resources provided by other applications.

2. Static source information
============================

For every contribution, the compiler records:

* the installed distribution name and version;
* the Python module that owns the resource;
* the resource path inside that module; and
* the schema version and content digest.

Together, these values identify the same source across deployment layouts. The loader reads them from the package and uses them as the source record.

The compiler records this information for each definition and role-permission assignment. For example, ``openedx-authz:openedx_authz/definitions/core.authz.yaml`` may assign ``courses.view_course`` to ``course_admin``, while ``course-authoring:course_authoring/authz/course_authoring.authz.yaml`` assigns ``courses.edit_schedule`` to the same role. Because both resources contributed to the compiled role, it keeps both source records.

3. Deployment command
=====================

``openedx-authz`` exposes one non-interactive command that discovers, validates, compiles, reports, and applies the static schema. For CI and local development, the same command can accept explicit resources or directories.

Tutor calls the command via for example a plugin initialization task, while other deployment systems call it before their application processes begin serving traffic. Each integration chooses the appropriate hook, but all of them use the same compiler.

4. Removed applications
=======================

When an application is disabled or removed, the next deployment removes the static definitions that came only from that application. If users are assigned to one of its roles, deployment stops and reports those assignments so that an operator can remove them or move the users to another role. Shared definitions remain available when another application still provides them.

Consequences
************

* An application can ship authorization definitions with its code.
* Tutor and other deployment systems use the same mechanism to discover and load the definitions.
* Source information remains consistent across container.
* Authorization changes after the deployment command runs successfully.
* Packaging checks must verify that schema resources are included in wheels and source distributions.
* Deployment integrations need to pass database settings and run the command at a point where all contributing packages are installed.

References
**********

* `ADR 0018`_
* `Tutor plugin development`_
* `Tutor plugin template`_

.. _ADR 0018: 0018-authorization-schema-lifecycle.rst
.. _Tutor plugin development: https://docs.tutor.edly.io/plugins/v0/gettingstarted.html
.. _Tutor plugin template: https://github.com/overhangio/cookiecutter-tutor-plugin/blob/master/%7B%7B%20cookiecutter.package_name%20%7D%7D/%7B%7B%20cookiecutter.module_name%20%7D%7D/plugin.py

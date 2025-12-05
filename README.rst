Open edX AuthZ
###############

|pypi-badge| |ci-badge| |codecov-badge| |doc-badge| |pyversions-badge|
|license-badge| |status-badge|

Purpose
*******

Open edX AuthZ provides the architecture and foundations of the authorization framework. It implements the core machinery needed to support consistent authorization across the Open edX ecosystem.

This repository centralizes the architecture, design decisions, and reference implementation of a unified model for roles and permissions. It introduces custom roles, flexible scopes, and policy-based evaluation, aiming to replace the fragmented legacy system with a scalable, extensible, and reusable solution.

See the `Product Requirements document for Roles & Permissions`_ for detailed specifications and requirements.

Integration with edx-platform
******************************

This repository became an edx-platform's dependency starting with the Ulmo release. From that release onwards, system policies are automatically updated.

If you need to update the policies manually, it is recommended to use the ``./manage.py lms load_policies`` command.

.. note::
    Currently, this package only supports the `content libraries' roles and permissions as documented here`_, and the migration of data from the old system to the new one is performed automatically.

    If you need to migrate the information manually, you should run ``./manage.py lms migrate openedx_authz``.


Getting Started with Development
********************************

Please see the Open edX documentation for `guidance on Python development`_ in this repo.

.. _guidance on Python development: https://docs.openedx.org/en/latest/developers/how-tos/get-ready-for-python-dev.html

Getting Help
************

Documentation
=============

See `documentation on Read the Docs <https://openedx-authz.readthedocs.io/en/latest/>`_.

More Help
=========

If you're having trouble, we have discussion forums at
https://discuss.openedx.org where you can connect with others in the
community.

Our real-time conversations are on Slack. You can request a `Slack
invitation`_, then join our `community Slack workspace`_.

For anything non-trivial, the best path is to open an issue in this
repository with as many details about the issue you are facing as you
can provide.

https://github.com/openedx/openedx-authz/issues
For more information about these options, see the `Getting Help <https://openedx.org/getting-help>`__ page.

.. _Slack invitation: https://openedx.org/slack
.. _community Slack workspace: https://openedx.slack.com/

License
*******

The code in this repository is licensed under the AGPL 3.0 unless
otherwise noted.

Please see `LICENSE <LICENSE>`_ for details.

Contributing
************

Contributions are very welcome.
Please read `How To Contribute <https://openedx.org/r/how-to-contribute>`_ for details.

This project is currently accepting all types of contributions, bug fixes,
security fixes, maintenance work, or new features.  However, please make sure
to discuss your new feature idea with the maintainers before beginning development
to maximize the chances of your change being accepted.
You can start a conversation by creating a new issue on this repo summarizing
your idea.

The Open edX Code of Conduct
****************************

All community members are expected to follow the `Open edX Code of Conduct`_.

.. _Open edX Code of Conduct: https://openedx.org/code-of-conduct/

People
******

The assigned maintainers for this component and other project details may be
found in `Backstage`_. Backstage pulls this data from the ``catalog-info.yaml``
file in this repo.

.. _Backstage: https://backstage.openedx.org/catalog/default/component/openedx-authz

Reporting Security Issues
*************************

Please do not report security issues in public. Please email security@openedx.org.


.. _Product Requirements document for Roles & Permissions: https://openedx.atlassian.net/wiki/spaces/OEPM/pages/4724490259/PRD+Roles+Permissions

.. _content libraries' roles and permissions as documented here: https://openedx-authz.readthedocs.io/en/latest/concepts/core_roles_and_permissions/content_library_roles.html

.. |pypi-badge| image:: https://img.shields.io/pypi/v/openedx-authz.svg
    :target: https://pypi.python.org/pypi/openedx-authz/
    :alt: PyPI

.. |ci-badge| image:: https://github.com/openedx/openedx-authz/actions/workflows/ci.yml/badge.svg?branch=main
    :target: https://github.com/openedx/openedx-authz/actions/workflows/ci.yml
    :alt: CI

.. |codecov-badge| image:: https://codecov.io/github/openedx/openedx-authz/coverage.svg?branch=main
    :target: https://codecov.io/github/openedx/openedx-authz?branch=main
    :alt: Codecov

.. |doc-badge| image:: https://readthedocs.org/projects/openedx-authz/badge/?version=latest
    :target: https://docs.openedx.org/projects/openedx-authz
    :alt: Documentation

.. |pyversions-badge| image:: https://img.shields.io/pypi/pyversions/openedx-authz.svg
    :target: https://pypi.python.org/pypi/openedx-authz/
    :alt: Supported Python versions

.. |license-badge| image:: https://img.shields.io/github/license/openedx/openedx-authz.svg
    :target: https://github.com/openedx/openedx-authz/blob/main/LICENSE.txt
    :alt: License

.. |status-badge| image:: https://img.shields.io/badge/Status-Experimental-yellow

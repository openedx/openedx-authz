.. _Generated Authorization Schema:

Generated Authorization Schema
##############################

This page renders the exact validation rules from the :download:`authz JSON Schema <../../openedx_authz/schema/authz-schema-v1.json>`. See the :doc:`Authorization Schema Reference <authorization-schema>` for guidance, examples, and validation performed by the compiler across schema contributions.

Top-level fields
****************

.. jsonschema:: ../../openedx_authz/schema/authz-schema-v1.json#/properties/schema_version
   :lift_description:

.. jsonschema:: ../../openedx_authz/schema/authz-schema-v1.json#/properties/priority
   :lift_description:

.. jsonschema:: ../../openedx_authz/schema/authz-schema-v1.json#/properties/permission_categories
   :lift_description:
   :hide_key: /items

.. jsonschema:: ../../openedx_authz/schema/authz-schema-v1.json#/properties/permissions
   :lift_description:
   :hide_key: /items

.. jsonschema:: ../../openedx_authz/schema/authz-schema-v1.json#/properties/roles
   :lift_description:
   :hide_key: /items

.. jsonschema:: ../../openedx_authz/schema/authz-schema-v1.json#/properties/role_extensions
   :lift_description:
   :hide_key: /items

Permission category fields
**************************

.. jsonschema:: ../../openedx_authz/schema/authz-schema-v1.json#/$defs/permission_category/properties/id
   :lift_description:

.. jsonschema:: ../../openedx_authz/schema/authz-schema-v1.json#/$defs/permission_category/properties/display_name
   :lift_description:

.. jsonschema:: ../../openedx_authz/schema/authz-schema-v1.json#/$defs/permission_category/properties/description
   :lift_description:

.. jsonschema:: ../../openedx_authz/schema/authz-schema-v1.json#/$defs/permission_category/properties/icon
   :lift_description:

Permission fields
*****************

.. jsonschema:: ../../openedx_authz/schema/authz-schema-v1.json#/$defs/permission/properties/namespace
   :lift_description:

.. jsonschema:: ../../openedx_authz/schema/authz-schema-v1.json#/$defs/permission/properties/name
   :lift_description:

.. jsonschema:: ../../openedx_authz/schema/authz-schema-v1.json#/$defs/permission/properties/display_name
   :lift_description:

.. jsonschema:: ../../openedx_authz/schema/authz-schema-v1.json#/$defs/permission/properties/description
   :lift_description:

.. jsonschema:: ../../openedx_authz/schema/authz-schema-v1.json#/$defs/permission/properties/category
   :lift_description:

.. jsonschema:: ../../openedx_authz/schema/authz-schema-v1.json#/$defs/permission/properties/scopes
   :lift_description:

.. jsonschema:: ../../openedx_authz/schema/authz-schema-v1.json#/$defs/permission/properties/icon
   :lift_description:

Role fields
***********

.. jsonschema:: ../../openedx_authz/schema/authz-schema-v1.json#/$defs/role/properties/id
   :lift_description:

.. jsonschema:: ../../openedx_authz/schema/authz-schema-v1.json#/$defs/role/properties/display_name
   :lift_description:

.. jsonschema:: ../../openedx_authz/schema/authz-schema-v1.json#/$defs/role/properties/description
   :lift_description:

.. jsonschema:: ../../openedx_authz/schema/authz-schema-v1.json#/$defs/role/properties/scopes
   :lift_description:

.. jsonschema:: ../../openedx_authz/schema/authz-schema-v1.json#/$defs/role/properties/permissions
   :lift_description:

.. jsonschema:: ../../openedx_authz/schema/authz-schema-v1.json#/$defs/role/properties/icon
   :lift_description:

.. jsonschema:: ../../openedx_authz/schema/authz-schema-v1.json#/$defs/role/properties/hidden
   :lift_description:

Role extension fields
*********************

.. jsonschema:: ../../openedx_authz/schema/authz-schema-v1.json#/$defs/role_extension/properties/role
   :lift_description:

.. jsonschema:: ../../openedx_authz/schema/authz-schema-v1.json#/$defs/role_extension/properties/add_permissions
   :lift_description:

.. jsonschema:: ../../openedx_authz/schema/authz-schema-v1.json#/$defs/role_extension/properties/remove_permissions
   :lift_description:

.. jsonschema:: ../../openedx_authz/schema/authz-schema-v1.json#/$defs/role_extension/properties/display_name
   :lift_description:

.. jsonschema:: ../../openedx_authz/schema/authz-schema-v1.json#/$defs/role_extension/properties/description
   :lift_description:

.. jsonschema:: ../../openedx_authz/schema/authz-schema-v1.json#/$defs/role_extension/properties/icon
   :lift_description:

.. jsonschema:: ../../openedx_authz/schema/authz-schema-v1.json#/$defs/role_extension/properties/hidden
   :lift_description:

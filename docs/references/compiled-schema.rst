.. _Compiled Authorization Schema:

Compiled Authorization Schema
#############################

The built-in applets each contribute part of the authorization schema, so a role's complete permission list only exists after the schema pipeline composes the base definitions with the ``role_extensions`` from every applet. This page shows that compiled result for the built-in applets, where each role lists its permissions grouped by the applet that adds them, and each permission and category names the applet that defines it. Installations may add more definitions through their own schema contributions, which this snapshot does not include.

The snapshot is generated from the applet schemas with ``make compiled_schema``, and a test fails when it no longer matches the compiled schema, so any change to an applet schema also shows its effect on the compiled roles in the same diff. You can also :download:`download the snapshot <compiled-schema.yaml>`.

.. literalinclude:: compiled-schema.yaml
   :language: yaml

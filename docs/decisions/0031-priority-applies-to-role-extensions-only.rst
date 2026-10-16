0031: Priority Applies Only to Role Extensions, Not Base Definitions
###################################################################

Status
******

**Draft**

Context
*******

The authorization schema is contributed as YAML files. Every file declares a
``priority`` number alongside its ``schema_version``, and that number applies to
all definitions in the file. `ADR 0017`_ and `ADR 0023`_ introduced ``priority``
for one purpose: to resolve conflicts between ``role_extensions``. When several
files change the same metadata field or the same permission on the same existing
role, the highest priority wins; an equal-priority disagreement is rejected.

Because ``priority`` sits at the top of every file and visually governs
everything below it, the YAML structure invites a reasonable but incorrect
assumption: that priority also decides a winner when two files declare the same
*base definition* differently. This ADR records that it does not, and explains
why, so the intent is visible to anyone reading the schema format later.

Two kinds of contribution matter here, and the distinction is the whole point:

* A **base definition** is a complete, self-contained declaration of a
  permission category, a permission, or a role. It is the single source of truth
  for that thing: a role's base definition *is* its full set of granted
  permissions and its display metadata.
* A **role extension** is an explicit, partial change to an existing base role.
  It adds or removes individual permissions, or replaces individual display
  fields. Priority exists to decide which change wins when two extensions touch
  the same field or the same permission.

Decision
********

Priority applies only to ``role_extensions``. It does **not** resolve conflicts
between base definitions.

Two files that declare the same permission category, permission, or role
identifier with differing content are a conflict, and validation rejects that
conflict as an error no matter what priorities the files declare. (Two files that
declare the identical base definition are not a conflict; that remains a
harmless duplicate.) Resolving such a disagreement is a deliberate authoring
decision, not something a priority number should settle silently.

We reach this decision for three reasons:

1. **Safety of access-control definitions.** A base definition is a complete
   grant of access. If priority could pick a winner, one file could silently
   replace another file's entire role — including the full set of permissions it
   grants — and the replaced definition would simply have no effect. A change
   that broadens or narrows what a role can do should be explicit and reviewable,
   never the quiet side effect of one file declaring a larger number than
   another.

2. **No need for it.** Deployments and applications adapt existing roles through
   ``role_extensions``, which exist precisely so a contributor can change a role
   without owning and restating its full definition (`ADR 0023`_). There is no
   requirement for two files to each fully redefine the same base definition and
   have one of them win.

3. **Base definitions stay a single source of truth.** A category, permission,
   or role is defined once; extensions are the mechanism for modifying it.
   Keeping that boundary sharp preserves clear provenance for every granted
   permission (`ADR 0025`_) and keeps the extension mechanism meaningful rather
   than redundant.

There is also a conceptual mismatch that makes "apply the same priority rule to
base definitions" less tidy than it sounds. Extension resolution is granular: it
compares one field or one permission at a time, so two files can change different
parts of the same role and both take effect. A base definition has no such
granularity — it would have to be replaced as a whole. Priority over base
definitions would therefore be an all-or-nothing override, which is exactly the
behavior the first reason argues against.

Wherever ``priority`` is documented, the text states that it governs role
extensions only, so a reader of the YAML format does not infer that it also
ranks competing base definitions.

Consequences
************

* Base definitions remain single-source-of-truth. A disagreement between two
  base definitions of the same category, permission, or role is surfaced as an
  error for an author to resolve, rather than resolved implicitly by priority.
* To adapt an existing role, contributors use ``role_extensions`` rather than a
  second, higher-priority base definition of the same role.
* Documentation of the ``priority`` field states plainly that it applies to role
  extensions only.
* If a future need ever arises to replace a whole base definition from a separate
  file, it will be introduced as its own explicitly designed and reviewable
  mechanism, not as an implicit consequence of priority.

References
**********

* `ADR 0017`_
* `ADR 0023`_
* `ADR 0025`_

.. _ADR 0017: 0017-static-authorization-schema.rst
.. _ADR 0023: 0023-extend-static-roles.rst
.. _ADR 0025: 0025-authorization-schema-source-tracking.rst

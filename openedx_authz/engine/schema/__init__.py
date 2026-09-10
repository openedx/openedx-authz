"""Authorization schema pipeline.

Turns on-disk ``.authz.yaml`` schema resources into a validated, compiled set of
static definitions, following the lifecycle defined in the authz ADRs:

    discover -> load -> validate -> compile   (this package, Casbin-free)
    render   -> apply                         (openedx_authz.engine.renderer)
    consume                                   (existing enforcer + APIs)

References:
    * ADR 0017 - static authorization schema (format)
    * ADR 0018 - authorization schema lifecycle (vocabulary + semantics)
    * ADR 0019 - authorization schema discovery (entry points + resources)
    * ADR 0023 - extend static roles (role_extensions merge rules)
    * docs/references/authorization-schema.rst - field-level reference
"""

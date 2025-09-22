0003: JWT usage
###############

Status
******

**Accepted** *2025-09-10*

Context
*******

Json Web Tokens (JWT) are a way for authenticating users in web
applications. The server generates a signed token that encodes the
user's identity and any relevant claims, which is then sent to the
client. The client includes this token in subsequent requests, allowing
the server to verify the user's identity without needing to maintain
session state.

Because the tokens are cryptographically signed, they can be efficiently
verified by the server without requiring database queries, which brings
performance and scalability benefits.

In addition to storing user identity, JWT tokens can also include
additional claims, such as user roles or permissions, which can be used
for authorization (AuthZ) purposes.

JWT is the `recommended way to authenticate with the Open edX REST API
<https://docs.openedx.org/projects/edx-platform/en/latest/how-tos/use_the_api.html>`_,
however, it's not widely used for AuthZ across the platform. One
exception is the `edx-rbac <https://github.com/openedx/edx-rbac>`_
library, which was a previous attempt to implement role-based access
control in the platform.

The edx-rbac library adds role information to the `"roles" claim in the
JWT token
<https://github.com/openedx/edx-rbac/blob/master/docs/how_to_guide.rst>`_
however, this is not widely used across the platform, being mostly used
on enterprise modules.

Given the new AuthZ project efforts, which seek to unify and simplify
AuthZ on Open edX, there is an opportunity to re-evaluate the use of JWT
tokens for Authorization purposes.

Possible Methods
================

#. Including AuthZ data in the JWT, attaching the user-related policies
   in the "policy" claim. Example implementation: `casbin-jwt-express
   <https://github.com/tiagostutz/casbin-jwt-express>`_

      -  Pros:

            -  No additional DB queries needed for AuthZ, which brings
               potential performance and scale benefits.

      -  Cons:

            -  JWT tokens can become large and unwieldy, potentially
               impacting request performance, increasing bandwidth
               usage, and hitting size limits.

            -  Changes in user roles or permissions will not be
               reflected in the token until it is refreshed, leading to
               potential security issues.

#. Not including AuthZ data in the JWT

      -  Pros:

            -  Smaller token size, leading to improved request
               performance and reduced bandwidth usage.
            -  Changes in user roles or permissions can be reflected
               immediately without requiring a token refresh.

      -  Cons:

            -  Additional DB queries may be needed for AuthZ, which
               could impact performance and scalability (could be
               mitigated with caching strategies).

Discussion
==========

The new AuthZ approach being discussed in this repository will allow for
a unified and more flexible way to manage authorization, this will allow
for more complex authorization scenarios to be handled more easily, for
example, specifying fine-grained access controls for libraries.

On a big instance, this will mean that the policies attached to a user
will potentially grow larger and more complex, which would greatly
increase the data that a JWT token would need to carry if we were to
include AuthZ data in the token itself.

On the other hand, the performance and resources impact of doing AuthZ
checks in the backend on every request can be mitigated with caching
strategies.

Decision
********

We will not include AuthZ data in the JWT tokens. JWT tokens will
continue to be used as an authentication mechanism, but AuthZ will be
handled separately in the backend.

Consequences
************

-  JWT tokens will continue to be used as they are currently, primarily
   for authentication purposes.
-  AuthZ will be handled in the backend, caching strategies should be
   considered to mitigate performance impacts.

Rejected Alternatives
*********************

-  Including AuthZ data in the JWT tokens by using the "policy" claim,
   including the full ACL definition for the user.

References
**********

- `edx-rbac how to guide <https://github.com/openedx/edx-rbac/blob/master/docs/how_to_guide.rst>`_
- `Example implementation of jwt embedded policies with casbin <https://github.com/tiagostutz/casbin-jwt-express>`_
- :ref:`OEP-66: Authorization Best Practices <openedx-proposals:OEP-66 User Authorization>`
- :ref:`Open edX Auth Overview Table <Open edX Auth Overview Table>`

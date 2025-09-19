0007: Enforcement mechanisms - communication with MFEs and other clients
#########################################################################

Status
********

**Draft**

Context
*********

Authorization (AuthZ) decisions need to be enforced not only on the
backend services, but also on the frontend applications, including
Micro-Frontends (MFEs) and mobile apps. This ensures that users only see
and can interact with the UI elements they are permitted to access based
on their roles and permissions.

To achieve this, we need to establish effective communication mechanisms
between the backend services and the frontend clients. This involves
determining how AuthZ data is transmitted, how often it is updated, and
how the frontend applications can use this data to enforce access
control.

We want an approach that:

-  Minimizes the amount of requests and data transferred between the
   backend and frontend.
-  Is granular enough to match the functionality available on the
   backend.
-  Is easy to implement and maintain across different frontend
   applications.

Decision
**********

I. REST API for authorization queries
=====================================

We will implement a dedicated REST API endpoint that frontend
applications can use to query for specific permissions. Queries would be
at the Subject-Action-Object-Context level, being the Subject always the
current authenticated user. This allows the frontend to check if a user
has permission to perform a specific action on a specific object within
a given context.

To optimize performance and reduce latency, the API will support batch
queries, allowing multiple permission checks in a single request. It
will also have caching mechanisms in place.

API Definition
--------------

POST /api/authz/v1/permissions/validate
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Validate if the current user has specific permissions.

Request Body:
"""""""""""""

Format:

.. code:: ts

   Array<{
       id: number
       action: string
       object?: string
       scope?: string
   }>

Example:

.. code:: json

   [
       {
           "id": 1,
           "action": "act:read",
           "object": "lib:test-lib",
           "scope": "org:OpenedX"
       },
       {
           "id": 2,
           "action": "act:edit",
           "object": "lib:test-lib",
           "scope": "org:OpenedX"
       }
   ]

**Please Note:**

-  id would be arbitrarily defined by the frontend/client as a way to
   keep track of each requested permission and match it with the response.
-  The user (subject) would be inferred from the authenticated user
   making the request.

Response Body:
""""""""""""""

Format:

.. code:: ts

   Array<{
       id: number
       allowed: boolean
   }>

Example:

.. code:: json

   [
       {
           "id": 1,
           "allowed": true
       },
       {
           "id": 2,
           "allowed": false
       }
   ]

Possible response codes:
""""""""""""""""""""""""

-  200: Ok, includes the Response Body defined above.
-  400: Bad Request, happens when the request body doesn't match the
   required format.
-  401: Unauthorized, happens when the user is not authenticated/logged in.

**Please note:** There is no “404 not found” case here, if the action,
object or scope doesn't exist, the “allowed” value in the response will
be whatever Casbin evaluates in this case.

II. Frontend integration
========================

Frontend applications will integrate with the REST API to enforce
authorization decisions. This will involve:

#. Querying the API for permissions when rendering UI components.
#. Using the API response to conditionally render or style UI elements
   based on the user's permissions.
#. Implementing a caching strategy on the frontend to minimize API calls
   and improve performance.

The specifics on when and how to query the API will depend on the
application's architecture and user interaction patterns.

Consequences
**************

-  The REST API approach provides a flexible and scalable way to enforce
   AuthZ decisions across different frontend applications.

-  It allows for real-time updates to permissions, as the frontend can
   query the API as needed.

-  The batch query and caching mechanisms help mitigate performance
   concerns, ensuring that the user experience remains smooth.

-  Frontend developers will need to implement the necessary logic to
   interact with the REST API and enforce AuthZ decisions.

-  The approach is adaptable to various frontend architectures,
   including MFEs and mobile apps, making it a versatile solution for
   the Open edX platform.

Rejected Alternatives
***********************

-  Embedding AuthZ data in JWT tokens: As discussed in `0003-jwt-usage`,
   embedding AuthZ data in JWT tokens can lead to large token sizes and
   stale permissions, in addition to having to re-implement Casbin model
   logic in the frontend.

-  Depending solely on backend enforcement on resource endpoints:
   Relying solely on backend enforcement can lead to a poor user
   experience, as users may see UI elements they cannot interact with,
   leading to confusion and frustration.

References
************

-  `Open edX REST API Conventions
   <https://openedx.atlassian.net/wiki/spaces/AC/pages/18350757/Open+edX+REST+API+Conventions>`_

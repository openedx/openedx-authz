"""Database models for the authorization framework.

These models will be used to store additional data about roles and permissions
that are not natively supported by Casbin, so as to avoid modifying the Casbin
schema that focuses on the core authorization logic.

For example, we may want to store metadata about roles, such as a description
or the date it was created.

This model is transversal to the implementation of the public API for
authorization, which is defined in openedx_authz.api. So it can be used by
various functions in the API to store and retrieve additional data about
roles and permissions. That's why we avoid coupling this model to too
specific concepts and also importing too specific classes from the API to
avoid circular dependencies.
"""

from openedx_authz.models.core import *
from openedx_authz.models.scopes import *
from openedx_authz.models.subjects import *

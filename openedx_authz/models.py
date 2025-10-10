"""
Database models for the authorization framework.

These models will be used to store additional data about roles and permissions
that are not natively supported by Casbin, so as to avoid modifying the Casbin
schema that focuses on the core authorization logic.

For example, we may want to store metadata about roles, such as a description
or the date it was created.
"""

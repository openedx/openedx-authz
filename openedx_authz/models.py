"""
Database models for the authorization framework.

These models will be used to store additional data about roles and permissions
that are not natively supported by Casbin, so as to avoid modifying the Casbin
schema that focuses on the core authorization logic.

For example, we may want to store metadata about roles, such as a description
or the date it was created.
"""
from django.db import models
from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType

User = get_user_model()

class ExtendedCasbinRule(models.Model):
    """Extended model for Casbin rules to store additional metadata.

    This model extends the CasbinRule model provided by the casbin_adapter
    package to include additional fields for storing metadata about each rule.
    """

    # Instead of making it 1:1 with the CasbinRule primary key which we usually don't know, let's
    # make an unique key based on the casbin_rule field which is a concatenation of all the fields
    # in the CasbinRule model. This way, we can easily look up the ExtendedCasbinRule
    # based on a policy line which SHOULD be unique.
    casbin_rule_key = models.CharField(max_length=255, unique=True)

    casbin_rule = models.OneToOneField(
        "casbin_adapter.CasbinRule",
        on_delete=models.CASCADE,
        related_name="extended_rule",
    )

    # We're assuming here that all scopes have a corresponding ContentType with an integer PK, which when
    # deleted, should cascade delete the associated ExtendedCasbinRule entries.
    # If this assumption does not hold, we may need to revisit this design.
    # TODO: I need to test this with actual models to ensure it works as expected.
    scope_content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE, null=True, blank=True)
    scope_id = models.PositiveIntegerField(null=True, blank=True)

    description = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    metadata = models.JSONField(blank=True, null=True)

    # To enable linking rules to users and other types of subjects, we can use a generic relation.
    subject_id = models.PositiveIntegerField(null=True, blank=True)
    subject_type = models.ForeignKey(ContentType, on_delete=models.CASCADE, null=True, blank=True)

    class Meta:
        verbose_name = "Extended Casbin Rule"
        verbose_name_plural = "Extended Casbin Rules"

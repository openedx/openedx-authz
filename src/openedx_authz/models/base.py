"""Shared abstract base models for the authorization framework.

These are reusable building blocks meant to remove field-level duplication
across the models package. They carry no table of their own (``abstract =
True``) and add no PII.
"""

from __future__ import annotations

from django.db import models

__all__ = [
    "SoftDeletableModel",
    "TimeStampedModel",
]


class TimeStampedModel(models.Model):
    """Abstract base adding self-managed ``created_at`` / ``updated_at`` timestamps.

    .. no_pii:

    Mirrors the ``created_at`` / ``updated_at`` convention already used across
    this repo (see :mod:`openedx_authz.models.core` and
    :mod:`openedx_authz.models.authz_migration`) rather than the ``created`` /
    ``modified`` names of :class:`model_utils.models.TimeStampedModel`, so
    adopting it needs no column renames. New models should inherit this instead
    of repeating the two fields; existing models can migrate to it over time.

    ``created_at`` is set once on insert (``auto_now_add``); ``updated_at`` is
    refreshed on every save (``auto_now``).
    """

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True


class SoftDeletableModel(models.Model):
    """Abstract base adding a ``removed_at`` timestamp, so a row can be removed without deleting it.

    .. no_pii:

    A removed row keeps its id and its relations, so unique identifiers stay reserved and audit
    records can still name it. ``removed_at`` is empty while the row is in use.

    Unlike :class:`model_utils.models.SoftDeletableModel`, this stores when the row was removed
    instead of an ``is_removed`` flag, and leaves the default manager alone: each model's queryset
    decides how removed rows are filtered.
    """

    removed_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="When the row was removed. Empty while it is in use.",
    )

    class Meta:
        abstract = True

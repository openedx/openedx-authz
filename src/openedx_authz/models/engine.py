"""Models for the authorization engine."""

from uuid import UUID, uuid4

from django.db import models


class PolicyCacheControl(models.Model):
    """Singleton row that both versions and guards the authorization policy.

    Its ``version`` is the cache-invalidation signal: whenever the stored policy
    changes, the version is bumped and every enforcer reloads on its next check
    (see :meth:`AuthzEnforcer.load_policy_if_needed`).

    Because this one row is also what every reader polls, it doubles as the
    natural serialization point for writers: :meth:`lock` takes an exclusive row
    lock on it so concurrent schema applies run one at a time. The lock lives
    here only as a thin primitive over this row; the *orchestration* of the
    critical section (ordering, enforcer reload, bumping the version inside the
    writer's transaction) belongs to the applier that owns the write, not to this
    model (see ``SchemaApplier._serialized_section``).

    .. no_pii:
    """

    version = models.UUIDField(default=uuid4)

    def save(self, *args, **kwargs):
        """Override save to ensure a single instance."""
        self.pk = 1  # Ensure a single instance
        super().save(*args, **kwargs)

    @classmethod
    def get(cls):
        """Get the singleton instance of the model."""
        obj, _ = cls.objects.get_or_create(pk=1)
        return obj

    @classmethod
    def ensure_exists(cls):
        """Create the singleton row if missing. Call *outside* the apply transaction.

        ``select_for_update`` cannot lock a row that does not exist, so the row
        has to be there before :meth:`lock` runs. This must be called before the
        apply ``transaction.atomic()`` block opens, not inside it: a plain
        ``SELECT``/INSERT inside that transaction would be its first read and,
        under InnoDB Repeatable Read, would pin the consistent-read snapshot
        *before* :meth:`lock` blocks — defeating the lock, because the post-lock
        reads would still see the pre-lock snapshot. Keeping row creation out of
        the apply transaction leaves the locking read in :meth:`lock` as the
        genuinely first read of that transaction.
        """
        cls.objects.get_or_create(pk=1)

    @classmethod
    def lock(cls):
        """Take an exclusive row lock on the singleton (``SELECT ... FOR UPDATE``).

        A thin serialization primitive: it blocks until any other transaction
        holding the lock commits or rolls back, then returns the row. It does not
        manage its own transaction or ordering — the caller owns both. For the
        lock to actually serialize a read-modify-write cycle it must be taken
        inside a ``transaction.atomic()`` block, as that transaction's first read
        (so the Repeatable Read snapshot forms after the lock is granted), and
        held across the reads and writes. ``SchemaApplier._serialized_section``
        is the orchestrator that satisfies those requirements; this method only
        provides the lock itself.

        :meth:`ensure_exists` must have run and committed first, since
        ``select_for_update`` cannot lock a row that does not exist yet.

        Returns:
            PolicyCacheControl: The locked singleton instance.
        """
        return cls.objects.select_for_update().get(pk=1)

    @classmethod
    def get_version(cls):
        """Get the version for policy cache control.

        Returns:
            UUID: The version of the last update.
        """
        instance = cls.get()
        return instance.version

    @classmethod
    def set_version(cls, version: UUID):
        """Update the cache version.

        This method updates the cache version, which can be used to signal
        that the policy cache should be invalidated.
        """
        instance = cls.get()
        instance.version = version

        instance.save()

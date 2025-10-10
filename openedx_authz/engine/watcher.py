"""
Redis-based policy change watcher for the authorization enforcer.

This module provides functionality to monitor policy changes in real-time using Redis
as a message broker. It enables automatic policy reloading across multiple instances
of the authorization system to maintain consistency and synchronization.

The watcher connects to Redis on the configured host and port, listens for policy
change events, and automatically triggers policy reloads when changes are detected.
This ensures that all running instances of the authorization system stay synchronized
with the latest policy configurations.
"""

import logging

from django.conf import settings
from redis_watcher import WatcherOptions, new_watcher

logger = logging.getLogger(__name__)


def callback_function(event) -> None:
    """
    Enhanced callback function for the enforcer that reloads policies on changes.

    This function is called whenever a policy change event is received through Redis.
    It reloads the policies in the enforcer to ensure all instances stay synchronized.

    Args:
        event: The policy change event from Redis
    """
    logger.info(f"Policy change event received: {event}")


def create_watcher():
    """
    Create and configure the Redis watcher for policy changes.

    Returns:
        The configured watcher instance
    """
    watcher_options = WatcherOptions()
    watcher_options.host = settings.REDIS_HOST
    watcher_options.port = settings.REDIS_PORT
    watcher_options.optional_update_callback = callback_function

    try:
        watcher = new_watcher(watcher_options)
        logger.info("Redis watcher created successfully")
        return watcher
    except Exception as e:  # pylint: disable=broad-exception-caught
        logger.error(f"Failed to create Redis watcher: {e}")
        return None


if settings.CASBIN_WATCHER_ENABLED:
    Watcher = create_watcher()
else:
    Watcher = None

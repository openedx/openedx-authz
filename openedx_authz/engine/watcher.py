"""
Watcher for the enforcer with enhanced policy reload capabilities.
"""

import logging

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
    watcher_options.host = "redis"
    watcher_options.port = 6379
    watcher_options.optional_update_callback = callback_function

    try:
        watcher = new_watcher(watcher_options)
        logger.info("Redis watcher created successfully")
        return watcher
    except Exception as e:
        logger.error(f"Failed to create Redis watcher: {e}")
        raise


Watcher = create_watcher()

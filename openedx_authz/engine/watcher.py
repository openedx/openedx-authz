"""
Watcher for the enforcer.
"""

from redis_watcher import WatcherOptions, new_watcher


def callback_function(event) -> None:
    """
    Callback function for the enforcer.
    """
    print("\nCallback function for the enforcer, event: {}".format(event))


watcher_options = WatcherOptions()
watcher_options.host = "redis"
watcher_options.port = 6379
watcher_options.optional_update_callback = callback_function
Watcher = new_watcher(watcher_options)

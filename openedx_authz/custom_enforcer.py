"""
Enforcer instance for openedx_authz.
"""

from dauthz.core import enforcer
from redis_watcher import WatcherOptions, new_watcher


def callback_function(event):
    """
    Callback function for the enforcer.
    """
    print("\n\nUpdate for remove filtered policy callback, event: {}".format(event))


def get_enforcer():
    """
    Get the enforcer instance.
    """
    enforcer.enable_auto_save(True)
    watcher_options = WatcherOptions()
    watcher_options.host = "redis"
    watcher_options.port = 6379
    watcher_options.optional_update_callback = callback_function
    watcher = new_watcher(watcher_options)
    enforcer.set_watcher(watcher)
    return enforcer

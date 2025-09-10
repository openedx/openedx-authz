"""
Enforcer instance for openedx_authz.
"""

from dauthz.core import enforcer
from redis_watcher import WatcherOptions, new_watcher


def callback_function(event):
    """Callback function for Redis watcher events."""
    print("\n\nUpdate for remove filtered policy callback, event: {}".format(event))

# Implement class Enforcer() that inherits from current enforcer and sets our defaults
# And uses our adapter by default

class Enforcer:

    # We might want our own cache configuration in the CACHE settings
    # so we default to those instead of hardcoding here
    def __init__(self, redis_host="redis", redis_port=6379, callback=None):
        """Initialize enforcer with Redis watcher configured."""
        # Store watcher configuration
        self._redis_host = redis_host
        self._redis_port = redis_port
        self._callback = callback or callback_function
        self._watcher = None

        # Configure the enforcer first
        enforcer.enable_auto_save(True)
        
        # Store the configured enforcer BEFORE setting up watcher
        self._enforcer = enforcer
        
        # Now set up the watcher
        self._setup_watcher()

    def _setup_watcher(self):
        """Set up the Redis watcher with current configuration."""
        watcher_options = WatcherOptions()
        watcher_options.host = self._redis_host
        watcher_options.port = self._redis_port
        watcher_options.optional_update_callback = self._callback
        self._watcher = new_watcher(watcher_options)
        self._enforcer.set_watcher(self._watcher)

    def configure_watcher(self, redis_host=None, redis_port=None, callback=None):
        """Dynamically reconfigure the Redis watcher."""
        if redis_host is not None:
            self._redis_host = redis_host
        if redis_port is not None:
            self._redis_port = redis_port
        if callback is not None:
            self._callback = callback

        # Reconfigure the watcher
        self._setup_watcher()

    @property
    def watcher_config(self):
        """Get current watcher configuration."""
        return {
            "host": self._redis_host,
            "port": self._redis_port,
            "callback": self._callback
        }

    def __getattr__(self, name):
        """Delegate all attribute access to the underlying enforcer."""
        return getattr(self._enforcer, name)

    def __setattr__(self, name, value):
        """Handle attribute setting for both internal and delegated attributes."""
        if name.startswith('_'):
            # Internal attributes (like _enforcer, _watcher, etc.)
            super().__setattr__(name, value)
        else:
            # Delegate to the underlying enforcer
            setattr(self._enforcer, name, value)

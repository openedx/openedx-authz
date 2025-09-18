"""
openedx_authz Django application initialization.
"""

from django.apps import AppConfig


class OpenedxAuthzConfig(AppConfig):
    """
    Configuration for the openedx_authz Django application.
    """

    name = "openedx_authz"
    verbose_name = "Open edX AuthZ"
    default_auto_field = "django.db.models.BigAutoField"

    plugin_app = {
        "url_config": {
            "lms.djangoapp": {
                "namespace": "openedx-authz",
                "regex": r"^openedx-authz/",
                "relative_path": "urls",
            },
            "cms.djangoapp": {
                "namespace": "openedx-authz",
                "regex": r"^openedx-authz/",
                "relative_path": "urls",
            },
        },
        "settings_config": {
            "lms.djangoapp": {
                "test": {"relative_path": "settings.test"},
                "common": {"relative_path": "settings.common"},
                "production": {"relative_path": "settings.production"},
            },
            "cms.djangoapp": {
                "test": {"relative_path": "settings.test"},
                "common": {"relative_path": "settings.common"},
                "production": {"relative_path": "settings.production"},
            },
        },
    }

    def ready(self):
        """
        Add admin users to the authorization policy.
        """
        # pylint: disable=import-outside-toplevel
        from django.contrib.auth import get_user_model

        from openedx_authz.custom_enforcer import get_enforcer

        enforcer = get_enforcer()

        # Add minimum policies for anonymous users
        anonymous_policies = [
            ("/", "*"),
            ("/login", "*"),
            ("/api/mfe_config/v1", "*"),
            ("/login_refresh", "*"),
            ("/csrf/api/v1/token", "*"),
            ("/api/user/v2/account/login_session/", "*"),
            ("/dashboard", "*"),
            ("/__debug__/history_sidebar/", "*"),
            ("/theming/asset/images/no_course_image.png", "*"),
        ]

        for resource, action in anonymous_policies:
            if not enforcer.has_policy("anonymous", resource, action):
                enforcer.add_policy("anonymous", resource, action)

        # Ensure admin users have access to all resources
        User = get_user_model()

        enforcer.add_policy("admin", "*", "*")
        admin_users = User.objects.filter(is_staff=True, is_superuser=True)
        for user in admin_users:
            enforcer.add_role_for_user(user.username, "admin")

        print("\n\nAdded default policies!\n\n")

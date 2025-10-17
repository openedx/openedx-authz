# In your openedx-authz/casbin_utils.py

from django.contrib.auth.models import User

from openedx.core.djangoapps.content_libraries.models import ContentLibrary
from cms.djangoapps.course_creators.views import get_course_creator_status
from opaque_keys.edx.locator import LibraryLocatorV2


def check_custom_conditions(request_user, request_action, request_scope):
    """
    Evaluates custom, non-role-based conditions using Bridgekeeper logic.
    """
    # Check if user exists
    try:
        user_id = request_user.split('^')[-1]
        user = User.objects.get(username=user_id) 
    except User.DoesNotExist:
        return False
    
    try:
        if request_scope != "*":
            scope_type = request_scope.split('^')[0]
            resource_id = request_scope.split('^')[-1]
            # Check if library exists
            if scope_type == "lib":
                try:
                    resource_parts = resource_id.split(':')
                    if len(resource_parts) < 3:
                        return False
                    org = resource_parts[1]
                    slug = resource_parts[2]
                    library_key = LibraryLocatorV2(org=org, slug=slug)
                    library = ContentLibrary.objects.get_by_key(library_key)
                except ContentLibrary.DoesNotExist:
                    return False
    except IndexError:
        return False

    # Global Staff Check
    # This is a general, high-privilege override
    if user.is_staff:
        return True # Global staff is always allowed

    # 3. Fine-Grained, Action-Specific Checks
    # For more complex checks, you define the logic here using Bridgekeeper syntax
    if request_action == "act^create_library":
        return get_course_creator_status(user) == 'granted'

    elif request_action == "act^view_library":
        return library.allow_public_read
    else:
        return False
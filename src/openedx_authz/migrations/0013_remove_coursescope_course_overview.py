from django.db import IntegrityError, migrations, transaction

KEY_CONFLICT_MESSAGE = (
    "Cannot copy the course key of these course scopes into external_key, because another scope "
    "already holds an equal key: {conflicts}. Resolve them as the openedx-authz how-to "
    '"Resolve Course Scopes That 0013_remove_coursescope_course_overview Cannot Update" describes, '
    "then run migrate again."
)


class CourseScopeKeyConflictError(Exception):
    """Raised when a course key cannot be copied into external_key because another scope holds it."""


def copy_course_keys_to_external_key(apps, schema_editor):
    """Copy the course key of each course scope without an external_key into external_key.

    Course scopes reference their course only by external_key once this migration removes
    course_overview. Scopes created before migration 0010_scope_external_key have no
    external_key, so their course key exists only in course_overview_id until it is copied.
    Each scope is updated in its own transaction, because external_key is unique and the
    database decides which keys are equal under its own collation. When any copy is rejected,
    the other scopes keep their copied key and the migration stops before the column is
    removed, so no course key is lost and running migrate again copies only the keys still
    missing. Nothing is updated when every course scope already has an external_key.

    Args:
        apps: The historical app registry of this migration.
        schema_editor: The schema editor running this migration.

    Returns:
        None

    Raises:
        CourseScopeKeyConflictError: When one or more course keys collide with an existing key,
            for example ``12: course-v1:OpenedX+DemoX+2024``.
    """
    course_scope_model = apps.get_model("openedx_authz", "CourseScope")
    scopes_without_key = course_scope_model.objects.filter(
        external_key__isnull=True,
        course_overview__isnull=False,
    ).values_list("pk", "course_overview_id")
    conflicts = []
    for scope_id, course_key in scopes_without_key:
        try:
            with transaction.atomic(using=schema_editor.connection.alias):
                course_scope_model.objects.filter(pk=scope_id).update(external_key=str(course_key))
        except IntegrityError:
            conflicts.append(f"{scope_id}: {course_key}")
    if conflicts:
        raise CourseScopeKeyConflictError(KEY_CONFLICT_MESSAGE.format(conflicts=", ".join(conflicts)))


class Migration(migrations.Migration):
    # Not atomic, so the keys copied before a conflict stay copied when the migration stops.
    atomic = False

    dependencies = [
        ("openedx_authz", "0012_move_builtin_schema_sources_to_applets"),
    ]

    operations = [
        migrations.RunPython(copy_course_keys_to_external_key, migrations.RunPython.noop),
        migrations.RemoveField(
            model_name="coursescope",
            name="course_overview",
        ),
    ]

"""Stub models for testing ContentLibrary-related functionality.

These models mimic the behavior of the actual models so the models can be
referenced in FK relationships without requiring the full application context.
"""

from django.conf import settings
from django.contrib.auth.models import Group
from django.db import models
from opaque_keys.edx.django.models import CourseKeyField, UsageKeyField
from opaque_keys.edx.locator import LibraryLocatorV2


class Organization(models.Model):
    """Stub model representing an organization for testing purposes.

    .. no_pii:
    """

    name = models.CharField(max_length=255)
    short_name = models.CharField(max_length=100)

    def __str__(self):
        return str(self.name)


class ContentLibraryManager(models.Manager):
    """Manager for ContentLibrary model with helper methods."""

    def get_by_key(self, library_key):
        """Get or create a ContentLibrary by its library key.

        Args:
            library_key: The library key to look up.

        Returns:
            ContentLibrary: The library instance.
        """
        if library_key is None:
            raise ValueError("library_key must not be None")
        try:
            key = str(LibraryLocatorV2.from_string(str(library_key)))
        except Exception:  # pylint: disable=broad-exception-caught
            key = str(library_key)
        obj, _ = self.get_or_create(locator=key)
        return obj


class ContentLibrary(models.Model):
    """Stub model representing a content library for testing purposes.

    .. no_pii:
    """

    locator = models.CharField(max_length=255, unique=True, db_index=True)
    title = models.CharField(max_length=255, blank=True, null=True)
    slug = models.SlugField(allow_unicode=True)
    org = models.ForeignKey(Organization, on_delete=models.PROTECT, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    objects = ContentLibraryManager()

    def __str__(self):
        return str(self.locator)


# Legacy permission models for testing purposes
class ContentLibraryPermission(models.Model):
    """Stub model representing legacy content library permissions for testing purposes.

    .. no_pii:
    """

    ADMIN_LEVEL = "admin"
    AUTHOR_LEVEL = "author"
    READ_LEVEL = "read"
    ACCESS_LEVEL_CHOICES = (
        (ADMIN_LEVEL, "Administer users and author content"),
        (AUTHOR_LEVEL, "Author content"),
        (READ_LEVEL, "Read-only"),
    )

    library = models.ForeignKey(ContentLibrary, on_delete=models.CASCADE)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, null=True, blank=True)
    group = models.ForeignKey(Group, on_delete=models.CASCADE, null=True, blank=True)
    access_level = models.CharField(max_length=30, choices=ACCESS_LEVEL_CHOICES)

    def __str__(self):
        who = self.user.username if self.user else self.group.name
        return f"ContentLibraryPermission ({self.access_level} for {who})"


class CourseOverview(models.Model):
    """
    Model for storing and caching basic information about a course.

    This model contains basic course metadata such as an ID, display name,
    image URL, and any other information that would be necessary to display
    a course as part of:
        user dashboard (enrolled courses)
        course catalog (courses to enroll in)
        course about (meta data about the course)

    .. no_pii:
    """

    class Meta:
        app_label = "course_overviews"

    # IMPORTANT: Bump this whenever you modify this model and/or add a migration.
    VERSION = 19

    # Cache entry versioning.
    version = models.IntegerField()

    # Course identification
    id = CourseKeyField(db_index=True, primary_key=True, max_length=255)
    _location = UsageKeyField(max_length=255)
    org = models.TextField(max_length=255, default="outdated_entry")
    display_name = models.TextField(null=True)
    display_number_with_default = models.TextField()
    display_org_with_default = models.TextField()

    start = models.DateTimeField(null=True)
    end = models.DateTimeField(null=True)

    # These are deprecated and unused, but cannot be dropped via simple migration due to the size of the downstream
    # history table. See DENG-19 for details.
    # Please use start and end above for these values.
    start_date = models.DateTimeField(null=True)
    end_date = models.DateTimeField(null=True)

    advertised_start = models.TextField(null=True)
    announcement = models.DateTimeField(null=True)

    # URLs
    # Not allowing null per django convention; not sure why many TextFields in this model do allow null
    banner_image_url = models.TextField()
    course_image_url = models.TextField()
    social_sharing_url = models.TextField(null=True)
    end_of_course_survey_url = models.TextField(null=True)

    # Certification data
    certificates_display_behavior = models.TextField(null=True)
    certificates_show_before_end = models.BooleanField(default=False)
    cert_html_view_enabled = models.BooleanField(default=False)
    has_any_active_web_certificate = models.BooleanField(default=False)
    cert_name_short = models.TextField()
    cert_name_long = models.TextField()
    certificate_available_date = models.DateTimeField(default=None, null=True)

    # Grading
    lowest_passing_grade = models.DecimalField(max_digits=5, decimal_places=2, null=True)

    # Access parameters
    days_early_for_beta = models.FloatField(null=True)
    mobile_available = models.BooleanField(default=False)
    visible_to_staff_only = models.BooleanField(default=False)
    _pre_requisite_courses_json = models.TextField()  # JSON representation of list of CourseKey strings

    # Enrollment details
    enrollment_start = models.DateTimeField(null=True)
    enrollment_end = models.DateTimeField(null=True)
    enrollment_domain = models.TextField(null=True)
    invitation_only = models.BooleanField(default=False)
    max_student_enrollments_allowed = models.IntegerField(null=True)

    # Catalog information
    catalog_visibility = models.TextField(null=True)
    short_description = models.TextField(null=True)
    course_video_url = models.TextField(null=True)
    effort = models.TextField(null=True)
    self_paced = models.BooleanField(default=False)
    marketing_url = models.TextField(null=True)
    eligible_for_financial_aid = models.BooleanField(default=True)

    # Course highlight info, used to guide course update emails
    has_highlights = models.BooleanField(null=True, default=None)  # if None, you have to look up the answer yourself

    # Proctoring
    enable_proctored_exams = models.BooleanField(default=False)
    proctoring_provider = models.TextField(null=True)
    proctoring_escalation_email = models.TextField(null=True)
    allow_proctoring_opt_out = models.BooleanField(default=False)

    # Entrance Exam information
    entrance_exam_enabled = models.BooleanField(default=False)
    entrance_exam_id = models.CharField(max_length=255, blank=True)
    entrance_exam_minimum_score_pct = models.FloatField(default=0.65)

    # Open Response Assessment configuration
    force_on_flexible_peer_openassessments = models.BooleanField(default=False)

    external_id = models.CharField(max_length=128, null=True, blank=True)

    language = models.TextField(null=True)

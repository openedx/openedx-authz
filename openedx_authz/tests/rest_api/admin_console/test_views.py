"""
Unit tests for the Admin-Console-specific REST API views.

These views (``ScopesAPIView``, ``AdminConsoleOrgsAPIView``, ``TeamMembersAPIView``,
``TeamMemberAssignmentsAPIView``, ``AssignmentsAPIView``) operate on Authorization's own
data but are shaped around the Admin Console's specific screens. See
``docs/decisions/0016-rest-api-domain-ownership-boundary.rst``.
"""

from unittest.mock import patch

from ddt import data, ddt, unpack
from django.contrib.auth import get_user_model
from django.urls import reverse
from organizations.models import Organization
from rest_framework import status

from openedx_authz.api.data import OrgContentLibraryGlobData, OrgCourseOverviewGlobData, PlatformCourseOverviewGlobData
from openedx_authz.api.users import assign_role_to_user_in_scope
from openedx_authz.constants import permissions, roles
from openedx_authz.models.scopes import get_content_library_model, get_course_overview_model
from openedx_authz.rest_api.v1.admin_console.views import ScopesAPIView
from openedx_authz.tests.rest_api.test_views import ViewTestMixin
from openedx_authz.tests.stubs.models import LearningPackage

ContentLibrary = get_content_library_model()
CourseOverview = get_course_overview_model()

User = get_user_model()

COURSE_SCOPE_ORG1 = "course-v1:Org1+COURSE1+2024"
COURSE_ORG1_GLOB = OrgCourseOverviewGlobData.build_external_key("Org1")
PLATFORM_COURSE_GLOB = PlatformCourseOverviewGlobData.build_external_key()

@ddt
class TestScopesAPIView(ViewTestMixin):
    """
    Test suite for ScopesAPIView.

    Setup summary (from ViewTestMixin.setUpClass):
        lib:Org1:LIB1 → admin_1 (library_admin), regular_1 (library_user), regular_2 (library_user)
        lib:Org2:LIB2 → admin_2 (library_user),  regular_3 (library_user),  regular_4 (library_user)
        lib:Org3:LIB3 → admin_3 (library_admin), regular_5 (library_admin), regular_6 (library_author),
                        regular_7 (library_contributor), regular_8 (library_user)

    Courses and ContentLibrary objects are mocked via get_scopes_for_user_and_permission
    and the queryset helper methods, since those models live in openedx-platform.
    """

    COURSE_ORG1 = COURSE_SCOPE_ORG1
    COURSE_ORG2 = "course-v1:Org2+COURSE2+2024"
    LIBRARY_ORG1 = "lib:Org1:LIB1"
    LIBRARY_ORG2 = "lib:Org2:LIB2"

    @classmethod
    def setUpClass(cls):
        """Assign course and library roles to test users."""
        super().setUpClass()
        cls._assign_roles_to_users(
            [
                # regular_9: can view course team on Org1 course
                {
                    "subject_name": "regular_9",
                    "role_name": roles.COURSE_STAFF.external_key,
                    "scope_name": cls.COURSE_ORG1,
                },
                # regular_10: can manage course team on Org2 course
                {
                    "subject_name": "regular_10",
                    "role_name": roles.COURSE_ADMIN.external_key,
                    "scope_name": cls.COURSE_ORG2,
                },
            ]
        )

    @classmethod
    def setUpTestData(cls):
        """Create Organization, CourseOverview and ContentLibrary fixtures."""
        super().setUpTestData()

        org1, _ = Organization.objects.get_or_create(name="Org1", short_name="Org1")
        org2, _ = Organization.objects.get_or_create(name="Org2", short_name="Org2")
        org3, _ = Organization.objects.get_or_create(name="Org3", short_name="Org3")

        CourseOverview.objects.get_or_create(
            id=cls.COURSE_ORG1, defaults={"org": "Org1", "display_name": "Course Org1"}
        )
        CourseOverview.objects.get_or_create(
            id=cls.COURSE_ORG2, defaults={"org": "Org2", "display_name": "Course Org2"}
        )

        lp1, _ = LearningPackage.objects.get_or_create(title="Library Org1")
        lp2, _ = LearningPackage.objects.get_or_create(title="Library Org2")
        lp3, _ = LearningPackage.objects.get_or_create(title="Library Org3")

        ContentLibrary.objects.get_or_create(
            slug="LIB1",
            org=org1,
            defaults={"locator": "lib:Org1:LIB1", "title": "Library Org1", "learning_package": lp1},
        )
        ContentLibrary.objects.get_or_create(
            slug="LIB2",
            org=org2,
            defaults={"locator": "lib:Org2:LIB2", "title": "Library Org2", "learning_package": lp2},
        )
        ContentLibrary.objects.get_or_create(
            slug="LIB3",
            org=org3,
            defaults={"locator": "lib:Org3:LIB3", "title": "Library Org3", "learning_package": lp3},
        )

    def setUp(self):
        """Set up test fixtures."""
        super().setUp()
        self.url = reverse("openedx_authz:scope-list")

        # Default combined result used by most tests.
        self.fake_scopes = [
            {
                "scope_id": self.COURSE_ORG1,
                "display_name_col": "Course Org1",
                "org_name": "Org1",
                "scope_type": "course",
            },
            {"scope_id": "LIB1", "display_name_col": "Library LIB1", "org_name": "Org1", "scope_type": "library"},
            {
                "scope_id": self.COURSE_ORG2,
                "display_name_col": "Course Org2",
                "org_name": "Org2",
                "scope_type": "course",
            },
            {"scope_id": "LIB2", "display_name_col": "Library LIB2", "org_name": "Org2", "scope_type": "library"},
        ]

        # Patch _build_queryset so tests don't need real DB querysets.
        self.build_qs_patcher = patch.object(
            ScopesAPIView,
            "_build_queryset",
            return_value=self.fake_scopes,
        )
        self.build_qs_patcher.start()
        self.addCleanup(self.build_qs_patcher.stop)

    # ------------------------------------------------------------------ #
    # Authentication                                                      #
    # ------------------------------------------------------------------ #

    def test_unauthenticated_returns_401(self):
        """Unauthenticated requests are rejected."""
        self.client.force_authenticate(user=None)

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    # ------------------------------------------------------------------ #
    # Response shape                                                      #
    # ------------------------------------------------------------------ #

    def test_response_shape(self):
        """Each result contains external_key, display_name, and org fields."""
        response = self.client.get(self.url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        for item in response.data["results"]:
            self.assertIn("external_key", item)
            self.assertIn("display_name", item)
            self.assertIn("org", item)

    # ------------------------------------------------------------------ #
    # Sorted by org                                                       #
    # ------------------------------------------------------------------ #

    def test_results_sorted_by_org(self):
        """Results are sorted by org_name across courses and libraries."""
        # Stop only build_qs_patcher; libraries_qs_patcher stays active (uses stub-compatible field name).
        self.build_qs_patcher.stop()

        response = self.client.get(self.url)  # admin_1 is staff, sees all

        self.build_qs_patcher.start()

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        org_names = [item["org"]["short_name"] if item["org"] else "" for item in response.data["results"]]
        self.assertEqual(org_names, sorted(org_names))

    # ------------------------------------------------------------------ #
    # type param                                                          #
    # ------------------------------------------------------------------ #

    @data(
        ("course", "_get_courses_queryset", "_get_libraries_queryset"),
        ("library", "_get_libraries_queryset", "_get_courses_queryset"),
    )
    @unpack
    def test_type_param_calls_only_expected_queryset(self, scope_type, called_method, skipped_method):
        """When type=course only courses are fetched; when type=library only libraries."""
        self.build_qs_patcher.stop()
        with (
            patch.object(ScopesAPIView, called_method, return_value=[]) as mock_called,
            patch.object(ScopesAPIView, skipped_method) as mock_skipped,
            patch.object(ScopesAPIView, "_build_queryset", return_value=[]),
        ):
            response = self.client.get(self.url, {"scope_type": scope_type})
        self.build_qs_patcher.start()

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        mock_called.assert_called_once()
        mock_skipped.assert_not_called()

    def test_type_param_invalid_returns_400(self):
        """An invalid type value returns 400."""
        response = self.client.get(self.url, {"scope_type": "invalid"})

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_type_param_absent_returns_both(self):
        """When type is not specified, both courses and libraries are returned."""
        self.build_qs_patcher.stop()
        with (
            patch.object(ScopesAPIView, "_get_courses_queryset", return_value=[]) as mock_courses,
            patch.object(ScopesAPIView, "_get_libraries_queryset", return_value=[]) as mock_libraries,
            patch.object(ScopesAPIView, "_build_queryset", return_value=[]),
        ):
            response = self.client.get(self.url)
        self.build_qs_patcher.start()

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        mock_courses.assert_called_once()
        mock_libraries.assert_called_once()

    # ------------------------------------------------------------------ #
    # Search                                                              #
    # ------------------------------------------------------------------ #

    def test_search_filters_by_display_name(self):
        """search param filters results by display_name."""
        # Search is applied pre-union inside get_queryset. Use real DB rows (staff user, type=course)
        # to avoid the union so the queryset remains filterable.
        self.build_qs_patcher.stop()

        response_match = self.client.get(self.url, {"search": "Course Org1", "scope_type": "course"})
        response_no_match = self.client.get(self.url, {"search": "nonexistent_xyz", "scope_type": "course"})

        self.build_qs_patcher.start()

        self.assertEqual(response_match.status_code, status.HTTP_200_OK)
        self.assertEqual(response_match.data["count"], 1)
        self.assertIn("Org1", response_match.data["results"][0]["display_name"])

        self.assertEqual(response_no_match.status_code, status.HTTP_200_OK)
        self.assertEqual(response_no_match.data["count"], 0)

    # ------------------------------------------------------------------ #
    # Pagination                                                          #
    # ------------------------------------------------------------------ #

    @data(
        ({"page": 1, "page_size": 1}, 1, True),
        ({"page": 2, "page_size": 1}, 1, True),
        ({"page": 3, "page_size": 1}, 1, False),
        ({"page": 1, "page_size": 3}, 3, False),
    )
    @unpack
    def test_pagination(self, query_params: dict, expected_page_count: int, has_next: bool):
        """Results are paginated correctly."""
        mixed = [
            {"scope_id": self.COURSE_ORG1, "display_name_col": "Course 1", "org_name": "Org1", "scope_type": "course"},
            {"scope_id": "LIB1", "display_name_col": "Library 1", "org_name": "Org1", "scope_type": "library"},
            {"scope_id": self.COURSE_ORG2, "display_name_col": "Course 2", "org_name": "Org2", "scope_type": "course"},
        ]
        self.build_qs_patcher.stop()
        with patch.object(ScopesAPIView, "_build_queryset", return_value=mixed):
            response = self.client.get(self.url, query_params)
        self.build_qs_patcher.start()

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], 3)
        self.assertEqual(len(response.data["results"]), expected_page_count)
        if has_next:
            self.assertIsNotNone(response.data["next"])
        else:
            self.assertIsNone(response.data["next"])

    # ------------------------------------------------------------------ #
    # Staff / superuser bypass                                            #
    # ------------------------------------------------------------------ #

    def test_staff_sees_all_scopes_without_permission_check(self):
        """Staff users bypass permission filtering and see all scopes."""
        with patch(
            "openedx_authz.rest_api.v1.admin_console.views.get_scopes_for_user_and_permission"
        ) as mock_get_scopes:
            response = self.client.get(self.url)  # admin_1 is staff

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        mock_get_scopes.assert_not_called()

    def test_non_staff_triggers_permission_check(self):
        """Non-staff users go through get_scopes_for_user_and_permission."""
        user = User.objects.get(username="regular_1")
        self.client.force_authenticate(user=user)

        with patch(
            "openedx_authz.rest_api.v1.admin_console.views.get_scopes_for_user_and_permission",
            return_value=[],
        ) as mock_get_scopes:
            response = self.client.get(self.url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(mock_get_scopes.call_count, 2)  # once per scope type

    # ------------------------------------------------------------------ #
    # Permission filtering: view                                          #
    # ------------------------------------------------------------------ #

    def test_view_permission_filters_courses_for_non_staff(self):
        """Non-staff user only sees courses they have VIEW_COURSE_TEAM permission for."""
        # regular_9 has COURSE_STAFF on COURSE_ORG1 → VIEW_COURSE_TEAM granted
        user = User.objects.get(username="regular_9")
        self.client.force_authenticate(user=user)
        self.build_qs_patcher.stop()

        response = self.client.get(self.url, {"scope_type": "course"})

        self.build_qs_patcher.start()
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        external_keys = [item["external_key"] for item in response.data["results"]]
        self.assertIn(self.COURSE_ORG1, external_keys)
        self.assertNotIn(self.COURSE_ORG2, external_keys)

    def test_view_permission_filters_libraries_for_non_staff(self):
        """Non-staff user only sees libraries they have VIEW_LIBRARY_TEAM permission for."""
        # regular_1 has LIBRARY_USER on lib:Org1:LIB1 → VIEW_LIBRARY_TEAM granted
        user = User.objects.get(username="regular_1")
        self.client.force_authenticate(user=user)
        self.build_qs_patcher.stop()

        response = self.client.get(self.url, {"scope_type": "library"})

        self.build_qs_patcher.start()
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        external_keys = [item["external_key"] for item in response.data["results"]]
        self.assertIn(self.LIBRARY_ORG1, external_keys)
        self.assertNotIn(self.LIBRARY_ORG2, external_keys)
        # Verify display_name is populated from the library title, not empty.
        for item in response.data["results"]:
            self.assertTrue(item["display_name"])

    def test_library_display_name_populated_in_standalone_path(self):
        """display_name is non-empty for libraries when type=library bypasses the union.

        Regression test: without aliasing learning_package__title as display_name,
        the standalone library queryset returns 'title' as the key and the serializer
        silently produces empty strings since it only reads 'display_name'.
        """
        user = User.objects.get(username="regular_1")
        self.client.force_authenticate(user=user)
        self.build_qs_patcher.stop()

        response = self.client.get(self.url, {"scope_type": "library"})

        self.build_qs_patcher.start()
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertGreater(response.data["count"], 0)
        for item in response.data["results"]:
            self.assertTrue(item["display_name"])

    # ------------------------------------------------------------------ #
    # Permission filtering: manage                                        #
    # ------------------------------------------------------------------ #

    def test_manage_permission_filters_courses_for_non_staff(self):
        """management_permission_only=true filters to courses with MANAGE_COURSE_TEAM only."""
        # regular_10 has COURSE_ADMIN on COURSE_ORG2 → MANAGE_COURSE_TEAM granted
        user = User.objects.get(username="regular_10")
        self.client.force_authenticate(user=user)
        self.build_qs_patcher.stop()

        response = self.client.get(self.url, {"scope_type": "course", "management_permission_only": "true"})

        self.build_qs_patcher.start()
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        external_keys = [item["external_key"] for item in response.data["results"]]
        self.assertIn(self.COURSE_ORG2, external_keys)
        self.assertNotIn(self.COURSE_ORG1, external_keys)

    def test_manage_permission_filters_libraries_for_non_staff(self):
        """management_permission_only=true filters to libraries with MANAGE_LIBRARY_TEAM only."""
        # regular_5 has LIBRARY_ADMIN on lib:Org3:LIB3 → MANAGE_LIBRARY_TEAM granted
        # regular_1 has LIBRARY_USER on lib:Org1:LIB1 → only VIEW, not MANAGE
        user = User.objects.get(username="regular_5")
        self.client.force_authenticate(user=user)
        self.build_qs_patcher.stop()

        response = self.client.get(self.url, {"scope_type": "library", "management_permission_only": "true"})

        self.build_qs_patcher.start()
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        external_keys = [item["external_key"] for item in response.data["results"]]
        self.assertIn("lib:Org3:LIB3", external_keys)
        self.assertNotIn(self.LIBRARY_ORG1, external_keys)

    def test_empty_allowed_library_pairs_returns_no_libraries(self):
        """When a non-staff user has no allowed libraries, no libraries are returned.

        Regression test: an empty allowed_pairs set must not bypass the filter
        and return all libraries (reduce with Q() default was a no-op).
        """
        # regular_9 has no library permissions, only a course role.
        user = User.objects.get(username="regular_9")
        self.client.force_authenticate(user=user)
        self.build_qs_patcher.stop()

        response = self.client.get(self.url, {"scope_type": "library"})

        self.build_qs_patcher.start()
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], 0)

    def test_empty_allowed_course_ids_returns_no_courses(self):
        """When a non-staff user has no allowed courses, no courses are returned.

        Regression test: an empty allowed_ids/allowed_orgs set must not bypass the filter
        and return all courses (empty Q() | empty Q() was a no-op).
        """
        # regular_1 has only library permissions, no course permissions.
        user = User.objects.get(username="regular_1")
        self.client.force_authenticate(user=user)
        self.build_qs_patcher.stop()

        response = self.client.get(self.url, {"scope_type": "course"})

        self.build_qs_patcher.start()
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], 0)

    def test_library_only_user_sees_no_courses_in_mixed_listing(self):
        """A user with only library permissions sees no courses in the default mixed listing.

        Regression test: without the empty-set guard, a user with library access but no
        course permissions would see all courses in the combined results.
        """
        # regular_1 has only library permissions, no course permissions.
        user = User.objects.get(username="regular_1")
        self.client.force_authenticate(user=user)
        self.build_qs_patcher.stop()

        response = self.client.get(self.url)

        self.build_qs_patcher.start()
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        scope_types = {item["external_key"].split(":")[0] for item in response.data["results"]}
        self.assertNotIn("course-v1", scope_types)
        self.assertIn("lib", scope_types)

    def test_org_glob_scope_returns_all_org_libraries(self):
        """A user with an org-level glob permission (lib:ORG:*) sees all libraries in that org."""
        user = User.objects.get(username="regular_1")
        self.client.force_authenticate(user=user)
        self.build_qs_patcher.stop()

        # Simulate get_scopes_for_user_and_permission returning an org-level glob.
        glob_scope = OrgContentLibraryGlobData(external_key="lib:Org1:*")
        with patch(
            "openedx_authz.rest_api.v1.admin_console.views.get_scopes_for_user_and_permission",
            return_value=[glob_scope],
        ):
            response = self.client.get(self.url, {"scope_type": "library"})

        self.build_qs_patcher.start()
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        external_keys = [item["external_key"] for item in response.data["results"]]
        self.assertIn(self.LIBRARY_ORG1, external_keys)
        self.assertNotIn(self.LIBRARY_ORG2, external_keys)

    def test_org_glob_scope_returns_all_org_courses(self):
        """A user with an org-level glob permission (course-v1:ORG+*) sees all courses in that org."""
        user = User.objects.get(username="regular_9")
        self.client.force_authenticate(user=user)
        self.build_qs_patcher.stop()

        # Simulate get_scopes_for_user_and_permission returning an org-level glob.
        glob_scope = OrgCourseOverviewGlobData(external_key=COURSE_ORG1_GLOB)
        with patch(
            "openedx_authz.rest_api.v1.admin_console.views.get_scopes_for_user_and_permission",
            return_value=[glob_scope],
        ):
            response = self.client.get(self.url, {"scope_type": "course"})

        self.build_qs_patcher.start()
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        external_keys = [item["external_key"] for item in response.data["results"]]
        self.assertIn(self.COURSE_ORG1, external_keys)
        self.assertNotIn(self.COURSE_ORG2, external_keys)

    def test_platform_glob_scope_returns_all_courses(self):
        """A user with platform-level glob (course-v1:*) sees all courses across orgs."""
        user = User.objects.get(username="regular_9")
        self.client.force_authenticate(user=user)
        self.build_qs_patcher.stop()

        platform_scope = PlatformCourseOverviewGlobData(external_key="course-v1:*")
        with patch(
            "openedx_authz.rest_api.v1.admin_console.views.get_scopes_for_user_and_permission",
            return_value=[platform_scope],
        ):
            response = self.client.get(self.url, {"scope_type": "course"})

        self.build_qs_patcher.start()
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        external_keys = [item["external_key"] for item in response.data["results"]]
        self.assertIn(self.COURSE_ORG1, external_keys)
        self.assertIn(self.COURSE_ORG2, external_keys)

    def test_manage_permission_only_uses_manage_permission(self):
        """management_permission_only=true calls get_admin_manage_permission, not get_admin_view_permission."""
        user = User.objects.get(username="regular_1")
        self.client.force_authenticate(user=user)

        with patch(
            "openedx_authz.rest_api.v1.admin_console.views.get_scopes_for_user_and_permission",
            return_value=[],
        ) as mock_get_scopes:
            self.client.get(self.url, {"management_permission_only": "true"})

        called_permissions = [call.args[1] for call in mock_get_scopes.call_args_list]
        self.assertIn(permissions.MANAGE_LIBRARY_TEAM.identifier, called_permissions)
        self.assertIn(permissions.COURSES_MANAGE_COURSE_TEAM.identifier, called_permissions)

    def test_view_permission_only_uses_view_permission(self):
        """management_permission_only=false (default) calls get_admin_view_permission."""
        user = User.objects.get(username="regular_1")
        self.client.force_authenticate(user=user)

        with patch(
            "openedx_authz.rest_api.v1.admin_console.views.get_scopes_for_user_and_permission",
            return_value=[],
        ) as mock_get_scopes:
            self.client.get(self.url)

        called_permissions = [call.args[1] for call in mock_get_scopes.call_args_list]
        self.assertIn(permissions.VIEW_LIBRARY_TEAM.identifier, called_permissions)
        self.assertIn(permissions.COURSES_VIEW_COURSE_TEAM.identifier, called_permissions)

    # ------------------------------------------------------------------ #
    # Org filter                                                          #
    # ------------------------------------------------------------------ #

    def test_org_filter_staff_courses(self):
        """Staff user with org param sees only courses from that org."""
        self.build_qs_patcher.stop()

        response = self.client.get(self.url, {"org": "Org1", "scope_type": "course"})

        self.build_qs_patcher.start()
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        for item in response.data["results"]:
            self.assertIn("Org1", item["external_key"])
        # Org2 course should not appear
        external_keys = [item["external_key"] for item in response.data["results"]]
        self.assertNotIn(self.COURSE_ORG2, external_keys)

    def test_org_filter_staff_libraries(self):
        """Staff user with org param sees only libraries from that org."""
        self.build_qs_patcher.stop()

        response = self.client.get(self.url, {"org": "Org2", "scope_type": "library"})

        self.build_qs_patcher.start()
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        external_keys = [item["external_key"] for item in response.data["results"]]
        self.assertIn(self.LIBRARY_ORG2, external_keys)
        self.assertNotIn(self.LIBRARY_ORG1, external_keys)

    def test_org_filter_staff_no_match(self):
        """Staff user with org param for a non-existent org gets empty results."""
        self.build_qs_patcher.stop()

        response = self.client.get(self.url, {"org": "NonExistentOrg", "scope_type": "course"})

        self.build_qs_patcher.start()
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], 0)

    def test_org_filter_non_staff_with_permission(self):
        """Non-staff user with org param sees scopes only if they have permission for that org."""
        # regular_1 has LIBRARY_USER on lib:Org1:LIB1 → VIEW_LIBRARY_TEAM granted
        user = User.objects.get(username="regular_1")
        self.client.force_authenticate(user=user)
        self.build_qs_patcher.stop()

        response = self.client.get(self.url, {"org": "Org1", "scope_type": "library"})

        self.build_qs_patcher.start()
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        external_keys = [item["external_key"] for item in response.data["results"]]
        self.assertIn(self.LIBRARY_ORG1, external_keys)

    def test_org_filter_non_staff_without_permission(self):
        """Non-staff user with org param for an org they have no permission for gets empty results."""
        # regular_1 has no permissions on Org2
        user = User.objects.get(username="regular_1")
        self.client.force_authenticate(user=user)
        self.build_qs_patcher.stop()

        response = self.client.get(self.url, {"org": "Org2", "scope_type": "library"})

        self.build_qs_patcher.start()
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], 0)

    def test_org_filter_non_staff_courses(self):
        """Non-staff user with org param sees only courses from that org if they have permission."""
        # regular_9 has COURSE_STAFF on COURSE_ORG1 → VIEW_COURSE_TEAM granted
        user = User.objects.get(username="regular_9")
        self.client.force_authenticate(user=user)
        self.build_qs_patcher.stop()

        response = self.client.get(self.url, {"org": "Org1", "scope_type": "course"})

        self.build_qs_patcher.start()
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        external_keys = [item["external_key"] for item in response.data["results"]]
        self.assertIn(self.COURSE_ORG1, external_keys)

    def test_org_filter_non_staff_courses_no_permission(self):
        """Non-staff user with org param for an org they have no course permission for gets empty results."""
        # regular_9 has no course permissions on Org2
        user = User.objects.get(username="regular_9")
        self.client.force_authenticate(user=user)
        self.build_qs_patcher.stop()

        response = self.client.get(self.url, {"org": "Org2", "scope_type": "course"})

        self.build_qs_patcher.start()
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], 0)

    def test_org_filter_with_glob_permission(self):
        """Non-staff user with org glob permission and org filter sees only that org's scopes."""
        user = User.objects.get(username="regular_1")
        self.client.force_authenticate(user=user)
        self.build_qs_patcher.stop()

        glob_scope = OrgContentLibraryGlobData(external_key="lib:Org1:*")
        with patch(
            "openedx_authz.rest_api.v1.admin_console.views.get_scopes_for_user_and_permission",
            return_value=[glob_scope],
        ):
            response = self.client.get(self.url, {"org": "Org1", "scope_type": "library"})

        self.build_qs_patcher.start()
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        external_keys = [item["external_key"] for item in response.data["results"]]
        self.assertIn(self.LIBRARY_ORG1, external_keys)
        self.assertNotIn(self.LIBRARY_ORG2, external_keys)

    def test_org_filter_with_glob_permission_wrong_org(self):
        """Non-staff user with org glob for Org1 but filtering by Org2 gets empty results."""
        user = User.objects.get(username="regular_1")
        self.client.force_authenticate(user=user)
        self.build_qs_patcher.stop()

        glob_scope = OrgContentLibraryGlobData(external_key="lib:Org1:*")
        with patch(
            "openedx_authz.rest_api.v1.admin_console.views.get_scopes_for_user_and_permission",
            return_value=[glob_scope],
        ):
            response = self.client.get(self.url, {"org": "Org2", "scope_type": "library"})

        self.build_qs_patcher.start()
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], 0)

    def test_org_filter_absent_returns_all_permitted(self):
        """When org param is absent, all permitted scopes are returned (existing behavior)."""
        self.build_qs_patcher.stop()

        response = self.client.get(self.url, {"scope_type": "course"})

        self.build_qs_patcher.start()
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Staff user sees all courses
        external_keys = [item["external_key"] for item in response.data["results"]]
        self.assertIn(self.COURSE_ORG1, external_keys)
        self.assertIn(self.COURSE_ORG2, external_keys)

    def test_org_filter_combined_with_search(self):
        """Org filter works together with search filter."""
        self.build_qs_patcher.stop()

        response = self.client.get(self.url, {"org": "Org1", "search": "Course", "scope_type": "course"})

        self.build_qs_patcher.start()
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        external_keys = [item["external_key"] for item in response.data["results"]]
        self.assertIn(self.COURSE_ORG1, external_keys)
        self.assertNotIn(self.COURSE_ORG2, external_keys)

    # ------------------------------------------------------------------ #
    # Orgs filter                                                          #
    # ------------------------------------------------------------------ #

    def test_orgs_filter_staff_courses(self):
        """Staff user with orgs param sees only courses from that org."""
        self.build_qs_patcher.stop()

        response = self.client.get(self.url, {"orgs": "Org1", "scope_type": "course"})

        self.build_qs_patcher.start()
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        for item in response.data["results"]:
            self.assertIn("Org1", item["external_key"])
        # Org2 course should not appear
        external_keys = [item["external_key"] for item in response.data["results"]]
        self.assertNotIn(self.COURSE_ORG2, external_keys)

    def test_orgs_filter_staff_libraries(self):
        """Staff user with orgs param sees only libraries from that org."""
        self.build_qs_patcher.stop()

        response = self.client.get(self.url, {"orgs": "Org2", "scope_type": "library"})

        self.build_qs_patcher.start()
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        external_keys = [item["external_key"] for item in response.data["results"]]
        self.assertIn(self.LIBRARY_ORG2, external_keys)
        self.assertNotIn(self.LIBRARY_ORG1, external_keys)

    def test_orgs_filter_staff_no_match(self):
        """Staff user with orgs param for a non-existent org gets empty results."""
        self.build_qs_patcher.stop()

        response = self.client.get(self.url, {"orgs": "NonExistentOrg", "scope_type": "course"})

        self.build_qs_patcher.start()
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], 0)

    def test_orgs_filter_non_staff_with_permission(self):
        """Non-staff user with orgs param sees scopes only if they have permission for that org."""
        # regular_1 has LIBRARY_USER on lib:Org1:LIB1 → VIEW_LIBRARY_TEAM granted
        user = User.objects.get(username="regular_1")
        self.client.force_authenticate(user=user)
        self.build_qs_patcher.stop()

        response = self.client.get(self.url, {"orgs": "Org1", "scope_type": "library"})

        self.build_qs_patcher.start()
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        external_keys = [item["external_key"] for item in response.data["results"]]
        self.assertIn(self.LIBRARY_ORG1, external_keys)

    def test_orgs_filter_non_staff_without_permission(self):
        """Non-staff user with org param for an org they have no permission for gets empty results."""
        # regular_1 has no permissions on Org2
        user = User.objects.get(username="regular_1")
        self.client.force_authenticate(user=user)
        self.build_qs_patcher.stop()

        response = self.client.get(self.url, {"orgs": "Org2", "scope_type": "library"})

        self.build_qs_patcher.start()
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], 0)

    def test_orgs_filter_non_staff_courses(self):
        """Non-staff user with orgs param sees only courses from that org if they have permission."""
        # regular_9 has COURSE_STAFF on COURSE_ORG1 → VIEW_COURSE_TEAM granted
        user = User.objects.get(username="regular_9")
        self.client.force_authenticate(user=user)
        self.build_qs_patcher.stop()

        response = self.client.get(self.url, {"orgs": "Org1", "scope_type": "course"})

        self.build_qs_patcher.start()
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        external_keys = [item["external_key"] for item in response.data["results"]]
        self.assertIn(self.COURSE_ORG1, external_keys)

    def test_orgs_filter_non_staff_courses_no_permission(self):
        """Non-staff user with orgs param for an org they have no course permission for gets empty results."""
        # regular_9 has no course permissions on Org2
        user = User.objects.get(username="regular_9")
        self.client.force_authenticate(user=user)
        self.build_qs_patcher.stop()

        response = self.client.get(self.url, {"orgs": "Org2", "scope_type": "course"})

        self.build_qs_patcher.start()
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], 0)

    def test_orgs_filter_with_glob_permission(self):
        """Non-staff user with orgs glob permission and org filter sees only that org's scopes."""
        user = User.objects.get(username="regular_1")
        self.client.force_authenticate(user=user)
        self.build_qs_patcher.stop()

        glob_scope = OrgContentLibraryGlobData(external_key="lib:Org1:*")
        with patch(
            "openedx_authz.rest_api.v1.admin_console.views.get_scopes_for_user_and_permission",
            return_value=[glob_scope],
        ):
            response = self.client.get(self.url, {"orgs": "Org1", "scope_type": "library"})

        self.build_qs_patcher.start()
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        external_keys = [item["external_key"] for item in response.data["results"]]
        self.assertIn(self.LIBRARY_ORG1, external_keys)
        self.assertNotIn(self.LIBRARY_ORG2, external_keys)

    def test_orgs_filter_with_glob_permission_wrong_org(self):
        """Non-staff user with org glob for Org1 but filtering by Org2 gets empty results."""
        user = User.objects.get(username="regular_1")
        self.client.force_authenticate(user=user)
        self.build_qs_patcher.stop()

        glob_scope = OrgContentLibraryGlobData(external_key="lib:Org1:*")
        with patch(
            "openedx_authz.rest_api.v1.admin_console.views.get_scopes_for_user_and_permission",
            return_value=[glob_scope],
        ):
            response = self.client.get(self.url, {"orgs": "Org2", "scope_type": "library"})

        self.build_qs_patcher.start()
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], 0)

    def test_orgs_filter_combined_with_search(self):
        """Orgs filter works together with search filter."""
        self.build_qs_patcher.stop()

        response = self.client.get(self.url, {"orgs": "Org1", "search": "Course", "scope_type": "course"})

        self.build_qs_patcher.start()
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        external_keys = [item["external_key"] for item in response.data["results"]]
        self.assertIn(self.COURSE_ORG1, external_keys)
        self.assertNotIn(self.COURSE_ORG2, external_keys)

    def test_orgs_filter_combined_with_org(self):
        """Orgs filter works together with the singluar org filter."""
        self.build_qs_patcher.stop()

        response = self.client.get(
            self.url, {"org": "Org2", "orgs": "Org1", "search": "Course", "scope_type": "course"}
        )

        self.build_qs_patcher.start()
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        external_keys = [item["external_key"] for item in response.data["results"]]
        self.assertIn(self.COURSE_ORG1, external_keys)
        self.assertIn(self.COURSE_ORG2, external_keys)

    def test_orgs_filter_with_multiple_orgs(self):
        """Orgs filter with multiple orgs returns scopes from both orgs."""
        self.build_qs_patcher.stop()

        response = self.client.get(self.url, {"orgs": "Org1,Org2", "search": "Course", "scope_type": "course"})

        self.build_qs_patcher.start()
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        external_keys = [item["external_key"] for item in response.data["results"]]
        self.assertIn(self.COURSE_ORG1, external_keys)
        self.assertIn(self.COURSE_ORG2, external_keys)


@ddt
class TestAdminConsoleOrgsAPIView(ViewTestMixin):
    """Test suite for AdminConsoleOrgsAPIView."""

    @classmethod
    def setUpClass(cls):
        """Assign a course role to regular_9 for COURSES_VIEW_COURSE_TEAM permission tests."""
        super().setUpClass()
        cls._assign_roles_to_users(
            [
                {
                    "subject_name": "regular_9",
                    "role_name": roles.COURSE_STAFF.external_key,
                    "scope_name": COURSE_SCOPE_ORG1,
                },
            ]
        )

    @classmethod
    def setUpTestData(cls):
        """Create Organization fixtures."""
        super().setUpTestData()

        Organization.objects.bulk_create(
            [
                Organization(name="Alpha University", short_name="AlphaU"),
                Organization(name="Beta Institute", short_name="BetaI"),
                Organization(name="Gamma College", short_name="GammaC"),
            ]
        )

    def setUp(self):
        """Set up test fixtures."""
        super().setUp()
        self.url = reverse("openedx_authz:orgs-list")

    def test_get_orgs_returns_all(self):
        """Test that all orgs are returned when no search param is provided.

        Expected result:
            - Returns 200 OK status
            - Returns all 3 orgs
        """
        response = self.client.get(self.url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], 3)
        self.assertEqual(len(response.data["results"]), 3)

    @data(
        # Match by name
        ("Alpha", 1),
        ("university", 1),
        # Match by short_name
        ("BetaI", 1),
        ("gamma", 1),
        # Partial match across multiple orgs
        ("a", 3),
        # No match
        ("nonexistent", 0),
    )
    @unpack
    def test_get_orgs_search(self, search_term: str, expected_count: int):
        """Test filtering orgs by name or short_name via the search param.

        Expected result:
            - Returns 200 OK status
            - Returns only orgs matching the search term
        """
        response = self.client.get(self.url, {"search": search_term})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], expected_count)
        self.assertEqual(len(response.data["results"]), expected_count)

    @data(
        ({}, 3, False),
        ({"page": 1, "page_size": 2}, 2, True),
        ({"page": 2, "page_size": 2}, 1, False),
        ({"page": 1, "page_size": 3}, 3, False),
    )
    @unpack
    def test_get_orgs_pagination(self, query_params: dict, expected_count: int, has_next: bool):
        """Test pagination of org results.

        Expected result:
            - Returns 200 OK status
            - Returns correct page size and next link
        """
        response = self.client.get(self.url, query_params)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["results"]), expected_count)
        if has_next:
            self.assertIsNotNone(response.data["next"])
        else:
            self.assertIsNone(response.data["next"])

    def test_get_orgs_response_shape(self):
        """Test that each org result contains the expected fields.

        Expected result:
            - Each result has id, name, and short_name fields
        """
        response = self.client.get(self.url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        result = response.data["results"][0]
        self.assertIn("id", result)
        self.assertIn("name", result)
        self.assertIn("short_name", result)

    def test_get_orgs_excludes_inactive(self):
        """Test that inactive orgs are not returned.

        Expected result:
            - Returns 200 OK status
            - Inactive orgs are excluded from results
        """
        Organization.objects.create(name="Inactive Org", short_name="InactiveO", active=False)

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], 3)
        result_names = [org["name"] for org in response.data["results"]]
        self.assertNotIn("Inactive Org", result_names)

    @data(
        # Only VIEW_LIBRARY_TEAM (library_user role in a lib scope)
        ("regular_1", status.HTTP_200_OK),
        # Only COURSES_VIEW_COURSE_TEAM (course_staff role in a course scope)
        ("regular_9", status.HTTP_200_OK),
        # No relevant permissions
        ("regular_10", status.HTTP_403_FORBIDDEN),
        # Superuser
        ("admin_1", status.HTTP_200_OK),
    )
    @unpack
    def test_get_orgs_permissions(self, username: str, expected_status: int):
        """Test access control for AdminConsoleOrgsAPIView.

        Test cases:
            - User with only VIEW_LIBRARY_TEAM (via library role): allowed
            - User with only COURSES_VIEW_COURSE_TEAM (via course role): allowed
            - User with neither permission: forbidden
            - Superuser/staff: allowed

        Expected result:
            - Returns appropriate status code based on user permissions

        """
        user = User.objects.get(username=username)
        self.client.force_authenticate(user=user)

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, expected_status)

    def test_get_orgs_user_with_both_permissions_allowed(self):
        """Test that a user with both VIEW_LIBRARY_TEAM and COURSES_VIEW_COURSE_TEAM can access the endpoint.

        Expected result:
            - Returns 200 OK status
        """
        # regular_1 has library_user (VIEW_LIBRARY_TEAM); assign a course role too
        self._assign_roles_to_users(
            [
                {
                    "subject_name": "regular_1",
                    "role_name": roles.COURSE_STAFF.external_key,
                    "scope_name": COURSE_SCOPE_ORG1,
                },
            ]
        )
        user = User.objects.get(username="regular_1")
        self.client.force_authenticate(user=user)

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_get_orgs_unauthenticated(self):
        """Test that unauthenticated requests are rejected.

        Expected result:
            - Returns 401 UNAUTHORIZED status

        """
        self.client.force_authenticate(user=None)

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


@ddt
class TestTeamMembersAPIView(ViewTestMixin):
    """
    Test suite for TeamMembersAPIView.

    Setup summary (from ViewTestMixin.setUpClass):
        lib:Org1:LIB1 → admin_1 (library_admin), regular_1 (library_user), regular_2 (library_user)  [3 users]
        lib:Org2:LIB2 → admin_2 (library_user),  regular_3 (library_user),  regular_4 (library_user) [3 users]
        lib:Org3:LIB3 → admin_3 (library_admin), regular_5 (library_admin), regular_6 (library_author),
                        regular_7 (library_contributor), regular_8 (library_user)                    [5 users]

    Total unique users with assignments: 11
    (admin_1..3 are staff/superuser; regular_1..8 are plain users)

    Visibility via filter_allowed_assignments:
        - Staff/superuser: sees all 11 users (is_admin_or_superuser_check grants VIEW_LIBRARY_TEAM on lib scopes)
        - regular_1 (library_user in Org1:LIB1): VIEW_LIBRARY_TEAM granted → sees Org1 members (3)
        - regular_3 (library_user in Org2:LIB2): VIEW_LIBRARY_TEAM granted → sees Org2 members (3)
        - regular_6 (library_author in Org3:LIB3): VIEW_LIBRARY_TEAM granted → sees Org3 members (5)
    """

    def setUp(self):
        """Set up test fixtures."""
        super().setUp()
        self.url = reverse("openedx_authz:user-list")

    # -------------------------------------------------------------------- #
    # Visibility: calling user only sees assignments it has view access to #
    # -------------------------------------------------------------------- #

    @data(
        # Staff/superuser sees all users across all scopes
        ("admin_1", status.HTTP_200_OK, 11),
        # regular_1 has LIBRARY_USER in lib:Org1:LIB1 (VIEW_LIBRARY_TEAM granted) → sees only Org1 members
        ("regular_1", status.HTTP_200_OK, 3),
        # regular_3 has LIBRARY_USER in lib:Org2:LIB2 (VIEW_LIBRARY_TEAM granted) → sees only Org2 members
        ("regular_3", status.HTTP_200_OK, 3),
        # regular_6 has LIBRARY_AUTHOR in lib:Org3:LIB3 (VIEW_LIBRARY_TEAM granted) → sees only Org3 members
        ("regular_6", status.HTTP_200_OK, 5),
        # regular_9 has no assignments → 403 (AnyScopePermission requires at least one relevant permission)
        ("regular_9", status.HTTP_403_FORBIDDEN, None),
    )
    @unpack
    def test_visibility_limited_to_accessible_scopes(
        self, username: str, expected_status: int, expected_count: int | None
    ):
        """Calling user only sees assignments for scopes it has VIEW_*_TEAM access to.

        Expected result:
            - Staff/superuser sees all users across all scopes.
            - Regular users only see members of scopes they have VIEW_*_TEAM permission for.
            - Users with no relevant permissions get 403.
        """
        user = User.objects.get(username=username)
        self.client.force_authenticate(user=user)

        response = self.client.get(self.url)
        self.assertEqual(response.status_code, expected_status)
        if expected_count is not None:
            self.assertEqual(response.data["count"], expected_count)

    def test_unauthenticated_returns_401(self):
        """Unauthenticated requests are rejected.

        Expected result:
            - Returns 401 UNAUTHORIZED.
        """
        self.client.force_authenticate(user=None)

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    # -------------------------------------------------------------------- #
    # Filter by scopes                                                     #
    # -------------------------------------------------------------------- #

    @data(
        # Single scope
        ("lib:Org1:LIB1", 3),
        ("lib:Org2:LIB2", 3),
        ("lib:Org3:LIB3", 5),
        # Multiple scopes (users are unique per scope, no overlap)
        ("lib:Org1:LIB1,lib:Org2:LIB2", 6),
        ("lib:Org1:LIB1,lib:Org3:LIB3", 8),
        ("lib:Org1:LIB1,lib:Org2:LIB2,lib:Org3:LIB3", 11),
        # Non-existent scope returns no results
        ("lib:Org99:NOLIB", 0),
    )
    @unpack
    def test_filter_by_scopes(self, scopes: str, expected_count: int):
        """Results are filtered to the requested scopes.

        Expected result:
            - Only users with assignments in the given scope(s) are returned.
            - Multiple scopes are OR-combined.
        """
        response = self.client.get(self.url, {"scopes": scopes})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], expected_count)

    # ------------------------------------------------------------------ #
    # Filter by orgs                                                     #
    # ------------------------------------------------------------------ #

    @data(
        # Single org
        ("Org1", 3),
        ("Org2", 3),
        ("Org3", 5),
        # Multiple orgs
        ("Org1,Org2", 6),
        ("Org1,Org3", 8),
        ("Org1,Org2,Org3", 11),
        # Non-existent org returns no results
        ("OrgX", 0),
    )
    @unpack
    def test_filter_by_orgs(self, orgs: str, expected_count: int):
        """Results are filtered to the requested orgs.

        Expected result:
            - Only users with assignments in the given org(s) are returned.
            - Multiple orgs are OR-combined.
        """
        response = self.client.get(self.url, {"orgs": orgs})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], expected_count)

    # ------------------------------------------------------------------ #
    # Search (username, full_name, email)                                #
    # ------------------------------------------------------------------ #

    @data(
        # Exact username match
        ("admin_1", 1),
        # Partial username match
        ("admin", 3),
        ("regular", 8),
        # Email match
        ("admin_1@example.com", 1),
        ("@example.com", 11),
        # No match
        ("nonexistent", 0),
    )
    @unpack
    def test_search(self, search: str, expected_count: int):
        """Search filters by username, full_name, or email (case-insensitive).

        Expected result:
            - Returns only users whose username, full_name, or email contains the search term.
        """
        response = self.client.get(self.url, {"search": search})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], expected_count)

    # ------------------------------------------------------------------ #
    # Sorting                                                            #
    # ------------------------------------------------------------------ #

    @data(
        ("username", "asc"),
        ("username", "desc"),
        ("email", "asc"),
        ("email", "desc"),
        ("full_name", "asc"),
        ("full_name", "desc"),
    )
    @unpack
    def test_sorting(self, sort_by: str, order: str):
        """Results can be sorted by username, full_name, or email in asc/desc order.

        Expected result:
            - Returns 200 OK.
            - Results are ordered according to the requested field and direction.
        """
        response = self.client.get(self.url, {"sort_by": sort_by, "order": order})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        values = [item[sort_by] for item in response.data["results"]]
        expected = sorted(values, key=lambda v: (v or "").lower(), reverse=order == "desc")
        self.assertEqual(values, expected)

    @data(
        {"sort_by": "invalid"},
        {"order": "ascending"},
        {"order": "descending"},
    )
    def test_sorting_invalid_params(self, query_params: dict):
        """Invalid sort_by or order values return 400.

        Expected result:
            - Returns 400 BAD REQUEST.
        """
        response = self.client.get(self.url, query_params)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    # ------------------------------------------------------------------ #
    # Pagination                                                         #
    # ------------------------------------------------------------------ #

    @data(
        ({"page": 1, "page_size": 5}, 5, True),
        ({"page": 2, "page_size": 5}, 5, True),
        ({"page": 3, "page_size": 5}, 1, False),
        ({"page": 1, "page_size": 11}, 11, False),
        ({"page": 1, "page_size": 6}, 6, True),
    )
    @unpack
    def test_pagination(self, query_params: dict, expected_page_count: int, has_next: bool):
        """Results are paginated correctly.

        Expected result:
            - Returns 200 OK.
            - Page contains the expected number of items.
            - `next` link is present only when more pages exist.
        """
        response = self.client.get(self.url, query_params)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], 11)
        self.assertEqual(len(response.data["results"]), expected_page_count)
        if has_next:
            self.assertIsNotNone(response.data["next"])
        else:
            self.assertIsNone(response.data["next"])

    # ------------------------------------------------------------------ #
    # Response shape                                                     #
    # ------------------------------------------------------------------ #

    def test_response_shape(self):
        """Each result item contains the expected fields.

        Expected result:
            - Returns 200 OK.
            - Each item has username, full_name, email, and assignation_count.
        """
        response = self.client.get(self.url, {"scopes": "lib:Org1:LIB1"})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        for item in response.data["results"]:
            self.assertIn("username", item)
            self.assertIn("full_name", item)
            self.assertIn("email", item)
            self.assertIn("assignation_count", item)
            self.assertEqual(item["assignation_count"], 1)


@ddt
class TestTeamMemberAssignmentsAPIView(ViewTestMixin):
    """
    Test suite for TeamMemberAssignmentsAPIView.

    Setup summary (from ViewTestMixin.setUpClass):
        lib:Org1:LIB1 → admin_1 (library_admin), regular_1 (library_user), regular_2 (library_user)
        lib:Org2:LIB2 → admin_2 (library_user),  regular_3 (library_user),  regular_4 (library_user)
        lib:Org3:LIB3 → admin_3 (library_admin), regular_5 (library_admin), regular_6 (library_author),
                        regular_7 (library_contributor), regular_8 (library_user)

    URL: /api/authz/v1/users/<username>/assignments/
    Response fields per item: is_superadmin, role, org, scope, permission_count

    Superadmin entry:
        admin_1..3 are staff/superusers. Querying any of them always adds one
        SuperAdminAssignmentData entry: role="django.superuser" (or "django.staff"),
        org="*", scope="*", permission_count=None, is_superadmin=True.
        This entry is always included regardless of org/role filters, since those
        filters are applied only to the role assignments, not to the superadmin entry.

    Visibility via filter_allowed_assignments:
        - Staff/superuser: sees all role assignments for any user, plus the superadmin
          entry when the target is a superadmin.
        - regular_1 (library_user in Org1:LIB1): sees only Org1:LIB1 role assignments,
          plus the superadmin entry when the target is a superadmin.
        - regular_9 (no assignments): rejected with 403 by AnyScopePermission
          (requires at least one VIEW_LIBRARY_TEAM or COURSES_VIEW_COURSE_TEAM permission).
    """

    def _url(self, username: str) -> str:
        return reverse("openedx_authz:user-assignment-list", kwargs={"username": username})

    # -------------------------------------------------------------------- #
    # Visibility: calling user only sees assignments it has view access to #
    # -------------------------------------------------------------------- #

    @data(
        # Staff/superuser targets get 1 superadmin entry + their role assignment(s)
        ("admin_1", "admin_1", status.HTTP_200_OK, 2),  # superadmin entry + library_admin in Org1
        ("admin_1", "admin_2", status.HTTP_200_OK, 2),  # superadmin entry + library_user in Org2
        ("admin_1", "admin_3", status.HTTP_200_OK, 2),  # superadmin entry + library_admin in Org3
        # Regular user targets get only their role assignments (no superadmin entry)
        ("admin_1", "regular_5", status.HTTP_200_OK, 1),
        # The superadmin entry is always included for superadmin targets, visible to all callers
        (
            "regular_1",
            "admin_1",
            status.HTTP_200_OK,
            2,
        ),  # superadmin entry + library_admin in Org1 (visible via Org1 access)
        # regular_1 cannot see admin_2's Org2 role assignment, but superadmin entry is still included
        ("regular_1", "admin_2", status.HTTP_200_OK, 1),  # superadmin entry only
        # regular_9 has no assignments → 403 (AnyScopePermission requires at least one relevant permission)
        ("regular_9", "admin_1", status.HTTP_403_FORBIDDEN, None),
    )
    @unpack
    def test_visibility_limited_to_accessible_scopes(
        self, caller: str, target: str, expected_status: int, expected_count: int | None
    ):
        """Calling user only sees role assignments for scopes it has view access to.

        The superadmin entry is always included when the target is a superadmin,
        regardless of the calling user's permissions.

        Expected result:
            - Superadmin targets always include the superadmin entry.
            - Role assignments are filtered by the calling user's permissions.
            - Regular user targets return only their visible role assignments.
            - Users with no relevant permissions get 403.
        """
        self.client.force_authenticate(user=User.objects.get(username=caller))

        response = self.client.get(self._url(target))

        self.assertEqual(response.status_code, expected_status)
        if expected_count is not None:
            self.assertEqual(response.data["count"], expected_count)

    def test_unauthenticated_returns_401(self):
        """Unauthenticated requests are rejected.

        Expected result:
            - Returns 401 UNAUTHORIZED.
        """
        self.client.force_authenticate(user=None)

        response = self.client.get(self._url("admin_1"))

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_unknown_user_returns_empty(self):
        """Requesting assignments for a non-existent user returns an empty list.

        Expected result:
            - Returns 200 OK with count 0.
        """
        response = self.client.get(self._url("nonexistent_user"))

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], 0)

    # ------------------------------------------------------------------ #
    # Filter by orgs                                                     #
    # ------------------------------------------------------------------ #

    @data(
        # admin_3 has library_admin in lib:Org3:LIB3; superadmin entry is always included
        ("admin_3", "Org3", 2),  # superadmin entry + Org3 role assignment
        ("admin_3", "Org1", 1),  # superadmin entry only (no Org1 role assignment)
        # regular_5 has library_admin in lib:Org3:LIB3 (no superadmin entry)
        ("regular_5", "Org3", 1),
        ("regular_5", "Org1", 0),
        # non-existent org: superadmin entry still included for admin targets
        ("admin_1", "OrgX", 1),  # superadmin entry only
    )
    @unpack
    def test_filter_by_orgs(self, target: str, orgs: str, expected_count: int):
        """Results are filtered to the requested orgs.

        Expected result:
            - Only assignments in the given org(s) are returned.
            - Multiple orgs are OR-combined.
        """
        response = self.client.get(self._url(target), {"orgs": orgs})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], expected_count)

    def test_filter_by_multiple_orgs(self):
        """Multiple orgs are OR-combined.

        Expected result:
            - Returns assignments matching any of the given orgs.
        """
        # regular_6 has library_author in lib:Org3:LIB3
        # regular_7 has library_contributor in lib:Org3:LIB3
        # Use admin_1 (staff) to see all of regular_8's assignments
        # regular_8 has library_user in lib:Org3:LIB3 only
        response = self.client.get(self._url("regular_8"), {"orgs": "Org1,Org3"})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], 1)

    # ------------------------------------------------------------------ #
    # Filter by roles                                                    #
    # ------------------------------------------------------------------ #

    @data(
        # role filter applies only to role assignments; superadmin entry is always included for admin targets
        ("admin_1", roles.LIBRARY_ADMIN.external_key, 2),  # superadmin entry + library_admin
        ("admin_1", roles.LIBRARY_USER.external_key, 1),  # superadmin entry only
        ("regular_5", roles.LIBRARY_ADMIN.external_key, 1),
        ("regular_5", roles.LIBRARY_USER.external_key, 0),
        ("regular_6", roles.LIBRARY_AUTHOR.external_key, 1),
        ("regular_6", roles.LIBRARY_ADMIN.external_key, 0),
        ("admin_1", "non_existent_role", 1),  # superadmin entry only
    )
    @unpack
    def test_filter_by_roles(self, target: str, role_filter: str, expected_count: int):
        """Results are filtered to the requested roles.

        Expected result:
            - Only assignments with the given role(s) are returned.
        """
        response = self.client.get(self._url(target), {"roles": role_filter})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], expected_count)

    def test_filter_by_multiple_roles(self):
        """Multiple roles are OR-combined for role assignments; superadmin entry always included.

        Expected result:
            - Returns assignments matching any of the given roles, plus the superadmin entry.
        """
        # admin_3 has library_admin in Org3:LIB3; filter for admin + author returns
        # 1 role assignment + 1 superadmin entry = 2
        response = self.client.get(
            self._url("admin_3"),
            {"roles": f"{roles.LIBRARY_ADMIN.external_key},{roles.LIBRARY_AUTHOR.external_key}"},
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], 2)

    # ------------------------------------------------------------------ #
    # Sorting                                                            #
    # ------------------------------------------------------------------ #

    @data(
        ("role", "asc"),
        ("role", "desc"),
        ("org", "asc"),
        ("org", "desc"),
        ("scope", "asc"),
        ("scope", "desc"),
    )
    @unpack
    def test_sorting(self, sort_by: str, order: str):
        """Results are sorted by role, org, or scope in asc/desc order.

        Uses admin_3, who has 2 items in the response: a superadmin entry
        (role="django.superuser", org="*", scope="*") and a role assignment
        (role="library_admin", org="Org3", scope="lib:Org3:LIB3"). With two
        distinct values per field the sort order is non-trivial and verifiable.

        Expected result:
            - Returns 200 OK.
            - Results are ordered according to the requested field and direction.
        """
        response = self.client.get(self._url("admin_3"), {"sort_by": sort_by, "order": order})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertGreater(len(response.data["results"]), 1)
        values = [item[sort_by] for item in response.data["results"]]
        expected = sorted(values, key=lambda v: (v or "").lower(), reverse=order == "desc")
        self.assertEqual(values, expected)

    @data(
        {"sort_by": "invalid"},
        {"sort_by": "username"},
        {"order": "ascending"},
        {"order": "descending"},
    )
    def test_sorting_invalid_params(self, query_params: dict):
        """Invalid sort_by or order values return 400.

        Expected result:
            - Returns 400 BAD REQUEST.
        """
        response = self.client.get(self._url("admin_1"), query_params)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    # ------------------------------------------------------------------ #
    # Pagination                                                         #
    # ------------------------------------------------------------------ #

    @data(
        ({"page": 1, "page_size": 1}, 1, True),
        ({"page": 2, "page_size": 1}, 1, False),
        ({"page": 1, "page_size": 2}, 2, False),
    )
    @unpack
    def test_pagination(self, query_params: dict, expected_page_count: int, has_next: bool):
        """Results are paginated correctly.

        Assigns regular_8 a second role (library_admin in Org1:LIB1) so it has
        2 assignments visible to admin_1 (staff).

        Expected result:
            - Returns 200 OK.
            - Page contains the expected number of items.
            - `next` link is present only when more pages exist.
        """
        assign_role_to_user_in_scope("regular_8", roles.LIBRARY_ADMIN.external_key, "lib:Org1:LIB1")

        response = self.client.get(self._url("regular_8"), query_params)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["results"]), expected_page_count)
        if has_next:
            self.assertIsNotNone(response.data["next"])
        else:
            self.assertIsNone(response.data["next"])

    def test_platform_glob_assignment_serializes_wildcard_org(self):
        """User with platform glob role assignment returns org '*' in the API response.

        regular_10 is assigned course_staff on course-v1:* (all courses on the platform).
        regular_9 is assigned course_admin on the same scope so they can view team
        assignments for that platform-level glob.
        """
        assign_role_to_user_in_scope("regular_10", roles.COURSE_STAFF.external_key, PLATFORM_COURSE_GLOB)
        assign_role_to_user_in_scope("regular_9", roles.COURSE_ADMIN.external_key, PLATFORM_COURSE_GLOB)

        self.client.force_authenticate(user=User.objects.get(username="regular_9"))
        response = self.client.get(self._url("regular_10"))

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], 1)
        assignment = response.data["results"][0]
        self.assertFalse(assignment["is_superadmin"])
        self.assertEqual(assignment["org"], "*")
        self.assertEqual(assignment["scope"], PLATFORM_COURSE_GLOB)
        self.assertEqual(assignment["role"], roles.COURSE_STAFF.external_key)

    # ------------------------------------------------------------------ #
    # Response shape                                                     #
    # ------------------------------------------------------------------ #

    def test_response_shape(self):
        """Each result item contains the expected fields.

        admin_1 is a superuser, so the response contains two items:
        - A superadmin entry with role="django.superuser", org="*", scope="*",
          permission_count=None, is_superadmin=True
        - A regular role assignment entry with concrete values and is_superadmin=False

        Expected result:
            - Returns 200 OK.
            - Each item has is_superadmin, role, org, scope, and permission_count.
        """
        response = self.client.get(self._url("admin_1"))

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], 2)

        superadmin_item = next(item for item in response.data["results"] if item["is_superadmin"])
        self.assertIn(superadmin_item["role"], ("django.superuser", "django.staff"))
        self.assertEqual(superadmin_item["org"], "*")
        self.assertEqual(superadmin_item["scope"], "*")
        self.assertIsNone(superadmin_item["permission_count"])

        role_item = next(item for item in response.data["results"] if not item["is_superadmin"])
        self.assertIn("role", role_item)
        self.assertIn("org", role_item)
        self.assertIn("scope", role_item)
        self.assertIn("permission_count", role_item)
        self.assertEqual(role_item["role"], roles.LIBRARY_ADMIN.external_key)
        self.assertEqual(role_item["org"], "Org1")
        self.assertEqual(role_item["scope"], "lib:Org1:LIB1")
        self.assertGreater(role_item["permission_count"], 0)




@ddt
class TestAssignmentsAPIView(ViewTestMixin):
    """
    Test suite for AssignmentsAPIView.

    Setup summary (from ViewTestMixin.setUpClass):
        lib:Org1:LIB1 → admin_1 (library_admin), regular_1 (library_user), regular_2 (library_user)
        lib:Org2:LIB2 → admin_2 (library_user),  regular_3 (library_user),  regular_4 (library_user)
        lib:Org3:LIB3 → admin_3 (library_admin), regular_5 (library_admin), regular_6 (library_author),
                        regular_7 (library_contributor), regular_8 (library_user)

    URL: /api/authz/v1/assignments/
    Response fields per item: is_superadmin, role, org, scope, permission_count, full_name, username, email

    This endpoint returns one row per (user, assignment) pair — i.e. assignments are
    "unpacked" so each row carries user info alongside the assignment fields.
    Total rows when called by a staff user with no filters:
        + 11 role assignments (see setup above)
        = 11 rows

    Visibility via get_visible_role_assignments_for_user:
        - Staff/superuser: sees all role assignments across all scopes.
        - regular_1 (library_user in Org1:LIB1): sees only Org1:LIB1 assignments (3).
        - regular_9 (no assignments): sees no role assignments.
    """

    def setUp(self):
        """Set up test fixtures."""
        super().setUp()
        self.url = reverse("openedx_authz:assignment-list")

    # -------------------------------------------------------------------- #
    # Visibility: calling user only sees assignments it has view access to #
    # -------------------------------------------------------------------- #

    @data(
        # Staff/superuser sees all: 11 role assignments
        ("admin_1", status.HTTP_200_OK, 11),
        # regular_1 has LIBRARY_USER in lib:Org1:LIB1 → sees 3 Org1 role assignments
        ("regular_1", status.HTTP_200_OK, 3),
        # regular_3 has LIBRARY_USER in lib:Org2:LIB2 → sees 3 Org2 role assignments
        ("regular_3", status.HTTP_200_OK, 3),
        # regular_6 has LIBRARY_AUTHOR in lib:Org3:LIB3 → sees 5 Org3 role assignments
        ("regular_6", status.HTTP_200_OK, 5),
        # regular_9 has no assignments → 403 (AnyScopePermission requires at least one relevant permission)
        ("regular_9", status.HTTP_403_FORBIDDEN, None),
    )
    @unpack
    def test_visibility_limited_to_accessible_scopes(
        self, username: str, expected_status: int, expected_count: int | None
    ):
        """Calling user only sees role assignments for scopes it has view access to.

        Users with no VIEW_LIBRARY_TEAM or COURSES_VIEW_COURSE_TEAM permission in any scope
        are rejected with 403 by AnyScopePermission.

        Expected result:
            - Staff/superuser sees all role assignments.
            - Regular users see only assignments for their accessible scopes.
            - Users with no relevant permissions get 403.
        """
        user = User.objects.get(username=username)
        self.client.force_authenticate(user=user)

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, expected_status)
        if expected_count is not None:
            self.assertEqual(response.data["count"], expected_count)

    def test_unauthenticated_returns_401(self):
        """Unauthenticated requests are rejected.

        Expected result:
            - Returns 401 UNAUTHORIZED.
        """
        self.client.force_authenticate(user=None)

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    # ------------------------------------------------------------------ #
    # Filter by orgs                                                     #
    # ------------------------------------------------------------------ #

    @data(
        ("Org1", 3),
        ("Org2", 3),
        ("Org3", 5),
        ("OrgX", 0),
    )
    @unpack
    def test_filter_by_orgs(self, orgs: str, expected_count: int):
        """Results are filtered to the requested orgs.

        Expected result:
            - Only role assignments in the given org(s) are returned.
        """
        response = self.client.get(self.url, {"orgs": orgs})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], expected_count)

    def test_filter_by_multiple_orgs(self):
        """Multiple orgs are OR-combined.

        Expected result:
            - Returns role assignments matching any of the given orgs.
        """
        # Org1 has 3 role assignments, Org2 has 3 → 6
        response = self.client.get(self.url, {"orgs": "Org1,Org2"})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], 6)

    # ------------------------------------------------------------------ #
    # Filter by roles                                                    #
    # ------------------------------------------------------------------ #

    @data(
        # library_admin: admin_1 (Org1), admin_3 (Org3), regular_5 (Org3) = 3
        (roles.LIBRARY_ADMIN.external_key, 3),
        # library_user: admin_2 (Org2), regular_1..4 (Org1+Org2), regular_8 (Org3) = 6
        (roles.LIBRARY_USER.external_key, 6),
        # library_author: regular_6 (Org3) = 1
        (roles.LIBRARY_AUTHOR.external_key, 1),
        # library_contributor: regular_7 (Org3) = 1
        ("library_contributor", 1),
        # Non-existent role: no matches
        ("non_existent_role", 0),
    )
    @unpack
    def test_filter_by_roles(self, role_filter: str, expected_count: int):
        """Results are filtered to the requested roles.

        Expected result:
            - Only role assignments with the given role(s) are returned.
        """
        response = self.client.get(self.url, {"roles": role_filter})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], expected_count)

    def test_filter_by_multiple_roles(self):
        """Multiple roles are OR-combined.

        Expected result:
            - Returns role assignments matching any of the given roles.
        """
        # library_admin (3) + library_author (1) = 4
        response = self.client.get(
            self.url,
            {"roles": f"{roles.LIBRARY_ADMIN.external_key},{roles.LIBRARY_AUTHOR.external_key}"},
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], 4)

    # ------------------------------------------------------------------ #
    # Filter by scopes                                                   #
    # ------------------------------------------------------------------ #

    @data(
        ("lib:Org1:LIB1", 3),
        ("lib:Org2:LIB2", 3),
        ("lib:Org3:LIB3", 5),
        ("lib:Org99:NOLIB", 0),
    )
    @unpack
    def test_filter_by_scopes(self, scopes: str, expected_count: int):
        """Results are filtered to the requested scopes.

        Expected result:
            - Only role assignments in the given scope(s) are returned.
        """
        response = self.client.get(self.url, {"scopes": scopes})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], expected_count)

    def test_filter_by_multiple_scopes(self):
        """Multiple scopes are OR-combined.

        Expected result:
            - Returns role assignments matching any of the given scopes.
        """
        # Org1 (3) + Org2 (3) = 6
        response = self.client.get(self.url, {"scopes": "lib:Org1:LIB1,lib:Org2:LIB2"})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], 6)

    # ------------------------------------------------------------------ #
    # Search (full_name, username, email)                                #
    # ------------------------------------------------------------------ #

    @data(
        # Exact username match — admin_1 has 1 role assignment
        ("admin_1", 1),
        # Partial username match — "admin" matches admin_1, admin_2, admin_3, each with 1 role assignment = 3
        ("admin", 3),
        # Partial username match — "regular" matches regular_1..8 (8 role assignments)
        ("regular", 8),
        # Email match
        ("admin_1@example.com", 1),
        # Partial email match — all 11 users have @example.com
        ("@example.com", 11),
        # No match
        ("nonexistent", 0),
    )
    @unpack
    def test_search(self, search: str, expected_count: int):
        """Search filters by full_name, username, or email (case-insensitive).

        Expected result:
            - Returns only assignments whose user's full_name, username, or email
              contains the search term.
        """
        response = self.client.get(self.url, {"search": search})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], expected_count)

    def test_search_case_insensitive(self):
        """Search is case-insensitive.

        Expected result:
            - Uppercase and lowercase search terms return the same results.
        """
        response_lower = self.client.get(self.url, {"search": "admin_1"})
        response_upper = self.client.get(self.url, {"search": "ADMIN_1"})

        self.assertEqual(response_lower.status_code, status.HTTP_200_OK)
        self.assertEqual(response_upper.status_code, status.HTTP_200_OK)
        self.assertEqual(response_lower.data["count"], response_upper.data["count"])

    # ------------------------------------------------------------------ #
    # Sorting                                                            #
    # ------------------------------------------------------------------ #

    @data(
        ("role", "asc"),
        ("role", "desc"),
        ("org", "asc"),
        ("org", "desc"),
        ("scope", "asc"),
        ("scope", "desc"),
        ("full_name", "asc"),
        ("full_name", "desc"),
        ("username", "asc"),
        ("username", "desc"),
        ("email", "asc"),
        ("email", "desc"),
    )
    @unpack
    def test_sorting(self, sort_by: str, order: str):
        """Results can be sorted by role, org, scope, full_name, username, or email.

        Expected result:
            - Returns 200 OK.
            - Results are ordered according to the requested field and direction.
        """
        response = self.client.get(self.url, {"sort_by": sort_by, "order": order})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertGreater(len(response.data["results"]), 1)
        values = [item[sort_by] for item in response.data["results"]]
        expected = sorted(values, key=lambda v: (v or "").lower(), reverse=order == "desc")
        self.assertEqual(values, expected)

    @data(
        {"sort_by": "invalid"},
        {"sort_by": "permission_count"},
        {"order": "ascending"},
        {"order": "descending"},
    )
    def test_sorting_invalid_params(self, query_params: dict):
        """Invalid sort_by or order values return 400.

        Expected result:
            - Returns 400 BAD REQUEST.
        """
        response = self.client.get(self.url, query_params)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    # ------------------------------------------------------------------ #
    # Pagination                                                         #
    # ------------------------------------------------------------------ #

    @data(
        # Total is 11 role assignments
        ({"page": 1, "page_size": 5}, 5, True),
        ({"page": 2, "page_size": 5}, 5, True),
        ({"page": 3, "page_size": 5}, 1, False),
        ({"page": 1, "page_size": 11}, 11, False),
        ({"page": 1, "page_size": 7}, 7, True),
        ({"page": 2, "page_size": 7}, 4, False),
    )
    @unpack
    def test_pagination(self, query_params: dict, expected_page_count: int, has_next: bool):
        """Results are paginated correctly.

        Expected result:
            - Returns 200 OK.
            - Page contains the expected number of items.
            - `next` link is present only when more pages exist.
        """
        response = self.client.get(self.url, query_params)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], 11)
        self.assertEqual(len(response.data["results"]), expected_page_count)
        if has_next:
            self.assertIsNotNone(response.data["next"])
        else:
            self.assertIsNone(response.data["next"])

    # ------------------------------------------------------------------ #
    # Response shape                                                     #
    # ------------------------------------------------------------------ #

    def test_response_shape(self):
        """Each result item contains the expected fields.

        Expected result:
            - Returns 200 OK.
            - Each item has is_superadmin, role, org, scope, permission_count,
              full_name, username, and email.
        """
        response = self.client.get(self.url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        expected_fields = {
            "is_superadmin",
            "role",
            "org",
            "scope",
            "permission_count",
            "full_name",
            "username",
            "email",
        }
        for item in response.data["results"]:
            self.assertEqual(set(item.keys()), expected_fields)

    def test_response_shape_role_assignment_entry(self):
        """Role assignment entries have the expected field values.

        Expected result:
            - Role assignment entries have is_superadmin=False, concrete role/org/scope
              values, a non-null permission_count, and populated user fields.
        """
        # Filter to a single scope to get predictable results
        response = self.client.get(self.url, {"scopes": "lib:Org1:LIB1"})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        role_items = [item for item in response.data["results"] if not item["is_superadmin"]]
        self.assertGreater(len(role_items), 0)
        for item in role_items:
            self.assertFalse(item["is_superadmin"])
            self.assertIn("role", item)
            self.assertEqual(item["org"], "Org1")
            self.assertEqual(item["scope"], "lib:Org1:LIB1")
            self.assertIsNotNone(item["permission_count"])
            self.assertGreater(item["permission_count"], 0)
            self.assertTrue(item["username"])
            self.assertTrue(item["email"])

    # ------------------------------------------------------------------ #
    # Superadmin entries                                                #
    # ------------------------------------------------------------------ #

    def test_no_superadmin_entries_in_response(self):
        """The list endpoint never returns superadmin entries.

        staff/superuser entries are not backed by Casbin policies and do not
        pass through the standard filter logic. They are excluded from this
        endpoint entirely.

        Expected result:
            - All items in the response have is_superadmin=False.
        """
        response = self.client.get(self.url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        for item in response.data["results"]:
            self.assertFalse(item["is_superadmin"])

    def test_no_superadmin_entries_when_filtering_by_org(self):
        """No superadmin entries appear even when an org filter is active.

        Expected result:
            - No items with is_superadmin=True in the response.
        """
        response = self.client.get(self.url, {"orgs": "NonExistentOrg"})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        superadmin_items = [item for item in response.data["results"] if item["is_superadmin"]]
        self.assertEqual(len(superadmin_items), 0)

    def test_no_superadmin_entries_when_filtering_by_role(self):
        """No superadmin entries appear even when a role filter is active.

        Expected result:
            - No items with is_superadmin=True in the response.
        """
        response = self.client.get(self.url, {"roles": roles.LIBRARY_ADMIN.external_key})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        superadmin_items = [item for item in response.data["results"] if item["is_superadmin"]]
        self.assertEqual(len(superadmin_items), 0)

    def test_no_superadmin_entries_when_filtering_by_scope(self):
        """No superadmin entries appear even when a scope filter is active.

        Expected result:
            - No items with is_superadmin=True in the response.
        """
        response = self.client.get(self.url, {"scopes": "lib:Org1:LIB1"})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        superadmin_items = [item for item in response.data["results"] if item["is_superadmin"]]
        self.assertEqual(len(superadmin_items), 0)

    def test_superadmin_user_search_returns_only_role_assignments(self):
        """Searching for a superadmin user returns only their role assignments.

        admin_1 is staff/superuser and has one role assignment (library_admin in Org1).
        The endpoint returns role assignments only, so the search result should be 1.

        Expected result:
            - Count is 1.
            - The result belongs to admin_1.
        """
        response = self.client.get(self.url, {"search": "admin_1"})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], 1)
        usernames = {item["username"] for item in response.data["results"]}
        self.assertEqual(usernames, {"admin_1"})

    def test_unprivileged_user_gets_403(self):
        """A user with no relevant permissions is rejected by AnyScopePermission.

        Expected result:
            - Returns 403 FORBIDDEN.
        """
        user = User.objects.get(username="regular_9")
        self.client.force_authenticate(user=user)

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    # ------------------------------------------------------------------ #
    # Combined filters                                                   #
    # ------------------------------------------------------------------ #

    def test_combined_org_and_role_filter(self):
        """Org and role filters can be combined.

        Expected result:
            - Only role assignments matching both the org and role are returned.
        """
        # library_admin in Org1 = admin_1 (1 assignment)
        response = self.client.get(
            self.url,
            {"orgs": "Org1", "roles": roles.LIBRARY_ADMIN.external_key},
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], 1)

    def test_combined_scope_and_search(self):
        """Scope filter and search can be combined.

        Expected result:
            - Results are filtered by scope first, then search is applied.
        """
        # Org1 has admin_1, regular_1, regular_2 → 3 role assignments
        # Search "regular" matches regular_1, regular_2 → 2 results
        response = self.client.get(
            self.url,
            {"scopes": "lib:Org1:LIB1", "search": "regular"},
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], 2)

    # ------------------------------------------------------------------ #
    # Active user filtering                                              #
    # ------------------------------------------------------------------ #

    def test_inactive_users_excluded_from_results(self):
        """Role assignments for inactive users are not included in results.

        Deactivating a user (is_active=False) should remove their role assignments
        from the response, even though the assignments still exist in the database.

        Expected result:
            - Returns 200 OK.
            - The inactive user's assignments do not appear in the results.
            - The total count decreases by the number of assignments the inactive user had.
        """
        # Baseline: admin_1 (staff) sees all 11 role assignments
        baseline_response = self.client.get(self.url)
        self.assertEqual(baseline_response.status_code, status.HTTP_200_OK)
        baseline_count = baseline_response.data["count"]

        # Deactivate regular_1, who has 1 role assignment in lib:Org1:LIB1
        inactive_user = User.objects.get(username="regular_1")
        inactive_user.is_active = False
        inactive_user.save()
        try:
            response = self.client.get(self.url)

            self.assertEqual(response.status_code, status.HTTP_200_OK)
            # regular_1 had 1 role assignment → count should drop by 1
            self.assertEqual(response.data["count"], baseline_count - 1)
            # Confirm regular_1 is not in the results
            usernames = {item["username"] for item in response.data["results"]}
            self.assertNotIn("regular_1", usernames)
        finally:
            inactive_user.is_active = True
            inactive_user.save()


@ddt
class TestAssignmentsAPIViewPermissions(ViewTestMixin):
    """
    Test suite for AssignmentsAPIView calling-user permission scenarios.

    This class extends the base ViewTestMixin setup with course-scope assignments
    to test cross-scope visibility rules.

    Base setup (from ViewTestMixin.setUpClass) — library scopes only:
        lib:Org1:LIB1 → admin_1 (library_admin), regular_1 (library_user), regular_2 (library_user)
        lib:Org2:LIB2 → admin_2 (library_user),  regular_3 (library_user),  regular_4 (library_user)
        lib:Org3:LIB3 → admin_3 (library_admin), regular_5 (library_admin), regular_6 (library_author),
                        regular_7 (library_contributor), regular_8 (library_user)

    Additional course-scope assignments (added in this class):
        course-v1:Org1+COURSE1+2024 → regular_9 (course_staff), regular_10 (course_auditor)

    Permission model:
        - Library scopes require VIEW_LIBRARY_TEAM to be visible.
        - Course scopes require COURSES_VIEW_COURSE_TEAM to be visible.
        - Superadmins (staff/superuser) bypass all permission checks and see everything.
        - Superadmin entries (from get_superadmin_assignments) are always included for all callers.

    Total role assignments after setup:
        11 library assignments + 2 course assignments = 13 role assignments
        + 3 superadmin entries (admin_1, admin_2, admin_3)
        = 16 total rows for a superadmin caller with no filters.
    """

    @classmethod
    def setUpClass(cls):
        """Add course-scope assignments on top of the base library assignments."""
        super().setUpClass()
        cls._assign_roles_to_users(
            [
                {
                    "subject_name": "regular_9",
                    "role_name": roles.COURSE_STAFF.external_key,
                    "scope_name": COURSE_SCOPE_ORG1,
                },
                {
                    "subject_name": "regular_10",
                    "role_name": roles.COURSE_AUDITOR.external_key,
                    "scope_name": COURSE_SCOPE_ORG1,
                },
            ]
        )

    def setUp(self):
        """Set up test fixtures."""
        super().setUp()
        self.url = reverse("openedx_authz:assignment-list")

    def test_superadmin_sees_all_assignments(self):
        """A superadmin caller sees all role assignments across all scope types.

        admin_1 is staff/superuser and bypasses all permission checks. The list
        endpoint does not include superadmin entries, only role assignments.

        Expected result:
            - Returns 200 OK.
            - Sees all 13 role assignments (no superadmin entries).
        """
        response = self.client.get(self.url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], 13)

    def test_superadmin_sees_library_and_course_assignments(self):
        """A superadmin caller sees both library and course scope assignments.

        Expected result:
            - Response includes assignments with both lib: and course-v1: scope prefixes.
        """
        response = self.client.get(self.url, {"page_size": 100})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        non_superadmin_items = [item for item in response.data["results"] if not item["is_superadmin"]]
        scopes = {item["scope"] for item in non_superadmin_items}
        lib_scopes = {s for s in scopes if s.startswith("lib:")}
        course_scopes = {s for s in scopes if s.startswith("course-v1:")}
        self.assertGreater(len(lib_scopes), 0)
        self.assertGreater(len(course_scopes), 0)

    # ------------------------------------------------------------------ #
    # No permissions at all                                              #
    # ------------------------------------------------------------------ #

    def test_user_without_any_permissions_gets_403(self):
        """A user with no role assignments at all is rejected by AnyScopePermission.

        AnyScopePermission requires the user to have at least one of
        VIEW_LIBRARY_TEAM or COURSES_VIEW_COURSE_TEAM in any scope.
        A user with no assignments has neither, so they get 403.

        Expected result:
            - Returns 403 FORBIDDEN.
        """
        no_perms_user, _ = User.objects.get_or_create(
            username="no_perms_user",
            defaults={"email": "no_perms@example.com"},
        )
        self.client.force_authenticate(user=no_perms_user)

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    # ------------------------------------------------------------------ #
    # Scoped permissions: courses only                                   #
    # ------------------------------------------------------------------ #

    def test_user_with_course_scope_permission_sees_course_assignments(self):
        """A user with COURSES_VIEW_COURSE_TEAM on a specific course sees those assignments.

        regular_9 has course_staff in course-v1:Org1+COURSE1+2024.
        course_staff includes COURSES_VIEW_COURSE_TEAM.

        Expected result:
            - Sees the 2 course assignments in course-v1:Org1+COURSE1+2024 (no superadmin entries).
            - Does NOT see any library assignments (no VIEW_LIBRARY_TEAM).
        """
        user = User.objects.get(username="regular_9")
        self.client.force_authenticate(user=user)

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], 2)

        non_superadmin_items = [item for item in response.data["results"] if not item["is_superadmin"]]
        # All non-superadmin items should be course assignments
        for item in non_superadmin_items:
            self.assertTrue(item["scope"].startswith("course-v1:"), f"Expected course scope, got {item['scope']}")

    def test_user_with_course_scope_permission_does_not_see_library_assignments(self):
        """A user with only course permissions cannot see library assignments.

        regular_9 has course_staff in course-v1:Org1+COURSE1+2024 but no library roles.

        Expected result:
            - No library-scope assignments appear in the results.
        """
        user = User.objects.get(username="regular_9")
        self.client.force_authenticate(user=user)

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        non_superadmin_items = [item for item in response.data["results"] if not item["is_superadmin"]]
        lib_items = [item for item in non_superadmin_items if item["scope"].startswith("lib:")]
        self.assertEqual(len(lib_items), 0)

    # ------------------------------------------------------------------ #
    # Scoped permissions: libraries only                                 #
    # ------------------------------------------------------------------ #

    def test_user_with_library_scope_permission_sees_library_assignments(self):
        """A user with VIEW_LIBRARY_TEAM on a specific library sees those assignments.

        regular_1 has library_user in lib:Org1:LIB1.
        library_user includes VIEW_LIBRARY_TEAM.

        Expected result:
            - Sees the 3 library assignments in lib:Org1:LIB1 (no superadmin entries).
            - Does NOT see any course assignments (no COURSES_VIEW_COURSE_TEAM).
        """
        user = User.objects.get(username="regular_1")
        self.client.force_authenticate(user=user)

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], 3)

        non_superadmin_items = [item for item in response.data["results"] if not item["is_superadmin"]]
        # All non-superadmin items should be library assignments
        for item in non_superadmin_items:
            self.assertTrue(item["scope"].startswith("lib:"), f"Expected library scope, got {item['scope']}")

    def test_user_with_library_scope_permission_does_not_see_course_assignments(self):
        """A user with only library permissions cannot see course assignments.

        regular_1 has library_user in lib:Org1:LIB1 but no course roles.

        Expected result:
            - No course-scope assignments appear in the results.
        """
        user = User.objects.get(username="regular_1")
        self.client.force_authenticate(user=user)

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        non_superadmin_items = [item for item in response.data["results"] if not item["is_superadmin"]]
        course_items = [item for item in non_superadmin_items if item["scope"].startswith("course-v1:")]
        self.assertEqual(len(course_items), 0)

    # ------------------------------------------------------------------ #
    # Org-level permissions: courses                                     #
    # ------------------------------------------------------------------ #

    def test_user_with_org_course_permission_sees_org_course_assignments(self):
        """A user with course_staff at org level sees all course assignments in that org.

        Assign regular_10 course_staff at org-level glob course-v1:Org1+* so they
        can see all course assignments in Org1.

        Expected result:
            - Sees course assignments in Org1.
            - Does NOT see library assignments.
        """
        self._assign_roles_to_users(
            [
                {
                    "subject_name": "regular_10",
                    "role_name": roles.COURSE_STAFF.external_key,
                    "scope_name": COURSE_ORG1_GLOB,
                },
            ]
        )
        user = User.objects.get(username="regular_10")
        self.client.force_authenticate(user=user)

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        non_superadmin_items = [item for item in response.data["results"] if not item["is_superadmin"]]
        # All non-superadmin items should be course assignments
        for item in non_superadmin_items:
            self.assertTrue(item["scope"].startswith("course-v1:"), f"Expected course scope, got {item['scope']}")
        # Should not see any library assignments
        lib_items = [item for item in non_superadmin_items if item["scope"].startswith("lib:")]
        self.assertEqual(len(lib_items), 0)

    # ------------------------------------------------------------------ #
    # Org-level permissions: libraries                                   #
    # ------------------------------------------------------------------ #

    def test_user_with_org_library_permission_sees_org_library_assignments(self):
        """A user with library_user at org level sees all library assignments in that org.

        Assign regular_9 library_user at org-level glob lib:Org1:* so they
        can see all library assignments in Org1, in addition to their existing
        course assignments.

        Expected result:
            - Sees library assignments in Org1 + course assignments + superadmin entries.
        """
        self._assign_roles_to_users(
            [
                {
                    "subject_name": "regular_9",
                    "role_name": roles.LIBRARY_USER.external_key,
                    "scope_name": "lib:Org1:*",
                },
            ]
        )
        user = User.objects.get(username="regular_9")
        self.client.force_authenticate(user=user)

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        non_superadmin_items = [item for item in response.data["results"] if not item["is_superadmin"]]
        lib_items = [item for item in non_superadmin_items if item["scope"].startswith("lib:")]
        course_items = [item for item in non_superadmin_items if item["scope"].startswith("course-v1:")]
        # Should see library assignments in Org1 (3 assignments)
        self.assertGreater(len(lib_items), 0)
        for item in lib_items:
            self.assertEqual(item["org"], "Org1")
        # Should also see course assignments (from their existing course_staff role)
        self.assertGreater(len(course_items), 0)

    def test_user_with_org_library_permission_does_not_see_other_org_libraries(self):
        """A user with org-level library permission only sees that org's library assignments.

        Assign regular_9 library_user at org-level glob lib:Org1:* — they should
        NOT see Org2 or Org3 library assignments.

        Expected result:
            - Library assignments are limited to Org1.
        """
        self._assign_roles_to_users(
            [
                {
                    "subject_name": "regular_9",
                    "role_name": roles.LIBRARY_USER.external_key,
                    "scope_name": "lib:Org1:*",
                },
            ]
        )
        user = User.objects.get(username="regular_9")
        self.client.force_authenticate(user=user)

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        non_superadmin_items = [item for item in response.data["results"] if not item["is_superadmin"]]
        lib_items = [item for item in non_superadmin_items if item["scope"].startswith("lib:")]
        lib_orgs = {item["org"] for item in lib_items}
        self.assertEqual(lib_orgs, {"Org1"})

    # ------------------------------------------------------------------ #
    # Mixed permissions: both library and course                         #
    # ------------------------------------------------------------------ #

    def test_user_with_both_library_and_course_permissions(self):
        """A user with permissions in both library and course scopes sees both.

        Assign regular_9 library_user at lib:Org1:* (in addition to their existing
        course_staff at course-v1:Org1+COURSE1+2024).

        Expected result:
            - Sees both library and course assignments + superadmin entries.
        """
        self._assign_roles_to_users(
            [
                {
                    "subject_name": "regular_9",
                    "role_name": roles.LIBRARY_USER.external_key,
                    "scope_name": "lib:Org1:*",
                },
            ]
        )
        user = User.objects.get(username="regular_9")
        self.client.force_authenticate(user=user)

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        non_superadmin_items = [item for item in response.data["results"] if not item["is_superadmin"]]
        scope_types = {item["scope"].split(":")[0] for item in non_superadmin_items}
        self.assertIn("lib", scope_types)
        self.assertIn("course-v1", scope_types)

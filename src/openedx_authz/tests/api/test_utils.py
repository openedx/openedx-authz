"""Unit tests for openedx_authz.api.utils."""

from django.test import TestCase
from organizations.models import Organization

from openedx_authz.api.data import GLOBAL_SCOPE_WILDCARD
from openedx_authz.api.utils import get_org_display_name_map


class TestGetOrgDisplayNameMap(TestCase):
    """Tests for resolving organization short names to display names."""

    @classmethod
    def setUpTestData(cls):
        """Create active and inactive organizations whose names differ from their short names."""
        Organization.objects.create(short_name="AlphaU", name="Alpha University")
        Organization.objects.create(short_name="BetaI", name="Beta Institute")
        Organization.objects.create(short_name="OldOrg", name="Retired Organization", active=False)

    def test_resolves_names_in_a_single_query(self):
        """All requested organizations are resolved with one query."""
        with self.assertNumQueries(1):
            result = get_org_display_name_map({"AlphaU", "BetaI"})

        self.assertEqual(result, {"AlphaU": "Alpha University", "BetaI": "Beta Institute"})

    def test_includes_inactive_organizations(self):
        """Inactive organizations still resolve, since existing assignments may point to them."""
        self.assertEqual(get_org_display_name_map({"OldOrg"}), {"OldOrg": "Retired Organization"})

    def test_omits_unknown_organizations(self):
        """Short names without a matching organization are left out of the result."""
        self.assertEqual(get_org_display_name_map({"AlphaU", "Missing"}), {"AlphaU": "Alpha University"})

    def test_wildcard_only_skips_the_query(self):
        """The global wildcard is not an organization, so no query runs for it."""
        with self.assertNumQueries(0):
            result = get_org_display_name_map({GLOBAL_SCOPE_WILDCARD})

        self.assertEqual(result, {})

    def test_empty_input_skips_the_query(self):
        """An empty set returns an empty map without querying."""
        with self.assertNumQueries(0):
            result = get_org_display_name_map(set())

        self.assertEqual(result, {})

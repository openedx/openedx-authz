"""
Scope parser fuzzing

Fuzz ``ScopeData(external_key=…)`` and ``ScopeData(namespaced_key=…)``
with random and known bad inputs.
"""

from __future__ import annotations

from unittest import TestCase

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from openedx_authz.api.data import (
    AUTHZ_POLICY_ATTRIBUTES_SEPARATOR,
    EXTERNAL_KEY_SEPARATOR,
    ContentLibraryData,
    OrgContentLibraryGlobData,
    OrgCourseOverviewGlobData,
    PlatformCourseOverviewGlobData,
    ScopeData,
)

# Namespace strings registered in the scope_registry, org_glob_registry, and
# platform_glob_registry. The base ScopeData registers "global", subclasses
# register "lib", "course-v1", "ccx-v1". We exclude "global" here because
# the "global" namespace accepts any external_key
# (ScopeData.validate_external_key is a no-op), which makes its namespaced_key
# fuzzing trivially pass without exercising the routing logic.
_KNOWN_NON_GLOBAL_NAMESPACES = frozenset({"lib", "course-v1", "ccx-v1"})

# Alphabet safe for generating org names / path segments
_SAFE_CHARS = st.characters(
    whitelist_categories=("Lu", "Ll", "Nd"),
    whitelist_characters="_.-",
)
_KEY_ALPHA = st.text(alphabet=_SAFE_CHARS, min_size=1, max_size=8)


# Check external_key parser
class TestExternalKeyParser(TestCase):
    """
    fuzz ``ScopeData(external_key=…)``.
    """

    @settings(
        max_examples=200,
    )
    @given(external_key=st.text())
    def test_no_unexpected_exceptions(self, external_key: str) -> None:
        """
        Only ``ValueError`` escapes from the external_key parser for any
        string input.

        A non-``ValueError`` exception leaking from the parser indicates an
        unguarded code path that should be addressed.
        """
        try:
            ScopeData(external_key=external_key)
        except ValueError:
            pass
        except Exception as exc:  # pylint: disable=broad-except
            self.fail(f"Unexpected {type(exc).__name__} for external_key={external_key!r}: {exc}")

    @settings(
        max_examples=200,
    )
    @given(external_key=st.text())
    def test_namespace_matches_prefix(self, external_key: str) -> None:
        """
        On success, ``scope.NAMESPACE`` equals the text before the first
        ``":"`` in ``external_key``.

        The global-wildcard special case (``external_key=="*"``) maps to
        base ``ScopeData`` with NAMESPACE ``"global"`` and is tested
        separately.
        """
        try:
            scope = ScopeData(external_key=external_key)
        except ValueError:
            return  # clean rejection

        if external_key == "*":
            self.assertEqual(
                scope.NAMESPACE,
                "global",
                msg="Global wildcard external_key='*' must map to NAMESPACE='global'.",
            )
            return

        # All other successful parses must contain ':' and have NAMESPACE ==
        # the prefix before it.
        self.assertIn(
            EXTERNAL_KEY_SEPARATOR,
            external_key,
            msg=(
                f"Parsing succeeded without '{EXTERNAL_KEY_SEPARATOR}' in "
                f"external_key={external_key!r} (not the '*' special case). "
                f"Returned type: {type(scope).__name__}, "
                f"NAMESPACE={scope.NAMESPACE!r}"
            ),
        )
        expected_ns = external_key.split(EXTERNAL_KEY_SEPARATOR, 1)[0]
        self.assertEqual(
            scope.NAMESPACE,
            expected_ns,
            msg=(
                f"NAMESPACE mismatch for external_key={external_key!r}: "
                f"expected {expected_ns!r}, got {scope.NAMESPACE!r} "
                f"(type: {type(scope).__name__})"
            ),
        )

    def test_global_wildcard_returns_base_scope_data(self) -> None:
        """
        ``ScopeData(external_key='*')`` returns the base ``ScopeData``
        instance, not a subclass, and has NAMESPACE ``'global'``.
        """
        scope = ScopeData(external_key="*")
        self.assertIs(type(scope), ScopeData)
        self.assertEqual(scope.NAMESPACE, "global")
        self.assertEqual(scope.external_key, "*")
        self.assertEqual(scope.namespaced_key, "global^*")

    def test_global_namespace_accepts_any_non_glob_key(self) -> None:
        """
        The ``global`` namespace uses a no-op ``validate_external_key``
        and accepts any non-glob external_key value.

        Note: keys containing ``"*"`` route through the glob-registry path
        *before* validation, so ``"global:*"`` raises ``ValueError`` (no
        platform-glob class is registered for the ``"global"`` namespace).
        Only non-glob keys bypass to the no-op validator.
        """
        for key in ("global:anything", "global:", "global:a:b:c", "global:some scope"):
            with self.subTest(key=key):
                scope = ScopeData(external_key=key)
                self.assertEqual(scope.NAMESPACE, "global")

        # Glob variants of "global:..." correctly raise ValueError because
        # no glob class is registered for the "global" namespace.
        for key in ("global:*", "global:foo*", "global:*bar"):
            with self.subTest(key=key):
                with self.assertRaises(ValueError):
                    ScopeData(external_key=key)


# Check namespaced_key parser
class TestNamespacedKeyParser(TestCase):
    """
    Fuzz ``ScopeData(namespaced_key=…)``.
    """

    @settings(
        max_examples=200,
    )
    @given(namespaced_key=st.text())
    def test_no_unexpected_exceptions(self, namespaced_key: str) -> None:
        """
        Only ``ValueError`` escapes from the namespaced_key parser for any
        string input.
        """
        try:
            ScopeData(namespaced_key=namespaced_key)
        except ValueError:
            pass  # clean rejection
        except Exception as exc:  # pylint: disable=broad-except
            self.fail(f"Unexpected {type(exc).__name__} for namespaced_key={namespaced_key!r}: {exc}")

    @settings(
        max_examples=100,
    )
    @given(
        namespace=st.sampled_from(sorted(_KNOWN_NON_GLOBAL_NAMESPACES)),
        suffix=st.text(
            # Exclude '*' (would trigger glob routing) and '^' (would confuse
            # the split) so this test focuses purely on routing and NAMESPACE
            # consistency.
            alphabet=st.characters(
                whitelist_categories=("Lu", "Ll", "Nd"),
                whitelist_characters="_.-:+",
            ),
            min_size=1,
            max_size=32,
        ),
    )
    def test_namespace_matches_prefix_for_known_namespaces(self, namespace: str, suffix: str) -> None:
        """
        When parsing a namespaced_key whose prefix belongs to a known registered
        namespace, the returned scope's NAMESPACE must equal that prefix.
        """
        nk = f"{namespace}{AUTHZ_POLICY_ATTRIBUTES_SEPARATOR}{suffix}"
        try:
            scope = ScopeData(namespaced_key=nk)
        except ValueError:
            return  # early rejection is fine

        self.assertEqual(
            scope.NAMESPACE,
            namespace,
            msg=(
                f"NAMESPACE mismatch for namespaced_key={nk!r}: "
                f"expected {namespace!r}, got {scope.NAMESPACE!r} "
                f"(type: {type(scope).__name__})"
            ),
        )


# Temporary tests for things that should be fixed.
class TestScopeParserFindings(TestCase):
    """
    Each test documents the *current* (potentially undesirable) behaviour.
    If the underlying bug is fixed, the relevant test will fail - that is
    the intended signal that the finding has been resolved and the test
    needs to be updated or removed.
    """

    # Unknown namespace in namespaced_key silently falls back
    def test_unknown_namespace_does_not_raise_value_error(self) -> None:
        """
        ``ScopeData(namespaced_key="nosuchns^something")``
        returns silently instead of raising ``ValueError``.

        The ``external_key`` path raises ``ValueError`` for the same unknown
        namespace (``ScopeData(external_key="nosuchns:something")`` ->
        ``ValueError``). The asymmetry means an attacker supplying a raw
        ``namespaced_key`` string from user input can construct a ``ScopeData``
        object with an inconsistent internal state.

        If this test starts failing (``ValueError`` is raised), this is
        resolved.
        """
        # external_key path correctly raises:
        with self.assertRaises(ValueError):
            ScopeData(external_key="nosuchns:something")

        # namespaced_key path does NOT raise - that is the bug:
        try:
            scope = ScopeData(namespaced_key="nosuchns^something")
        except ValueError:
            self.fail(
                "Bug may be resolved: ValueError was raised for an unknown "
                "namespace prefix via the namespaced_key path. "
                "This test can be updated or removed."
            )

        # Confirm the fallback: ScopeData base class with NAMESPACE="global"
        self.assertIs(type(scope), ScopeData)
        self.assertEqual(
            scope.NAMESPACE,
            "global",
            msg=(
                "Expected fallback NAMESPACE='global' for "
                "unknown prefix 'nosuchns'. Got something else - "
                "the fallback behaviour changed."
            ),
        )

    def test_fallback_produces_inconsistent_object_state(self) -> None:
        """
        ``scope.namespaced_key`` starts with the unknown prefix ``"nosuchns"``
        but ``scope.NAMESPACE`` is ``"global"``. Re-deriving the namespaced
        key from NAMESPACE + external_key produces a *different* value,
        meaning code that relies on one source of truth will disagree with
        code that relies on the other.
        """
        scope = ScopeData(namespaced_key="nosuchns^some_external_key")

        # The key's declared prefix and NAMESPACE disagree:
        key_prefix = "nosuchns^some_external_key".split(AUTHZ_POLICY_ATTRIBUTES_SEPARATOR, 1)[0]
        self.assertNotEqual(
            scope.NAMESPACE,
            key_prefix,
            msg="NAMESPACE should not match the unknown key prefix 'nosuchns'.",
        )

        # Re-constructing the namespaced key from NAMESPACE+external_key yields
        # a different value than the stored namespaced_key:
        reconstructed = f"{scope.NAMESPACE}{AUTHZ_POLICY_ATTRIBUTES_SEPARATOR}{scope.external_key}"
        self.assertNotEqual(
            reconstructed,
            scope.namespaced_key,
            msg=(
                "Reconstructed namespaced_key should differ from stored "
                "namespaced_key (evidence of inconsistent state). "
                "If they are now equal, the fallback was fixed and "
                "this test can be removed."
            ),
        )

    # namespaced_key path bypasses validate_external_key()
    def test_invalid_external_key_accepted_via_namespaced_key(self) -> None:
        """
        The ``namespaced_key`` code path does not call ``validate_external_key()``.

        A ``ContentLibraryData`` instance can be created with a syntactically
        invalid library key via the ``namespaced_key`` route, bypassing the
        ``LibraryLocatorV2`` validation that the ``external_key`` path
        enforces.

        Downstream callers that invoke ``scope.get_object()`` or assume a
        valid locator will still raise an error when they try to use the
        malformed key. However, code that trusts this return of a
        ContentLibraryData as evidence of a parse-able library key will be
        surprised.

        If this test starts failing (``ValueError`` raised via
        ``namespaced_key`` path), the issue is resolved - update accordingly.
        """
        invalid_key = "lib:NOTAVALIDLIBRARYKEY"  # no 3-part lib:org:slug format

        # external_key path enforces validation -> raises:
        with self.assertRaises(
            ValueError,
            msg="external_key path must call validate_external_key() and reject the malformed key",
        ):
            ScopeData(external_key=invalid_key)

        # namespaced_key path skips validation -> silently creates the object:
        try:
            scope = ScopeData(namespaced_key=f"lib{AUTHZ_POLICY_ATTRIBUTES_SEPARATOR}{invalid_key}")
        except ValueError:
            self.fail(
                "Bug may be resolved: ValueError raised for a malformed "
                "library key via the namespaced_key path. This test can be updated "
                "or removed."
            )

        self.assertIsInstance(
            scope,
            ContentLibraryData,
            msg="Expected ContentLibraryData via the 'lib^' prefix",
        )
        self.assertEqual(
            scope.external_key,
            invalid_key,
            msg="external_key should be stored verbatim without validation",
        )


# Glob routing consistency
@st.composite
def _lib_org_glob(draw) -> str:
    """
    Generate a valid ``lib:{org}:*`` external_key.
    """
    return f"lib:{draw(_KEY_ALPHA)}:*"


@st.composite
def _course_org_glob(draw) -> str:
    """
    Generate a valid ``course-v1:{org}+*`` external_key.
    """
    return f"course-v1:{draw(_KEY_ALPHA)}+*"


class TestGlobRoutingConsistency(TestCase):
    """
    Glob routing never crosses namespace boundaries.

    A glob ``external_key`` whose declared namespace prefix is ``"lib"``
    must return a scope whose NAMESPACE is ``"lib"``, and similarly for
    ``"course-v1"``.
    """

    @settings(
        max_examples=100,
    )
    @given(external_key=_lib_org_glob())
    def test_lib_org_glob_routes_to_lib_namespace(self, external_key: str) -> None:
        """
        ``lib:{org}:*`` routes to ``OrgContentLibraryGlobData`` with
        NAMESPACE ``"lib"``.
        """
        try:
            scope = ScopeData(external_key=external_key)
        except ValueError:
            return  # org name rejected by validator - fine

        self.assertEqual(
            scope.NAMESPACE,
            "lib",
            msg=(
                f"Glob routing crossed namespace boundary: {external_key!r} "
                f"routed to {type(scope).__name__} with "
                f"NAMESPACE={scope.NAMESPACE!r}"
            ),
        )
        self.assertIsInstance(
            scope,
            OrgContentLibraryGlobData,
            msg=f"{external_key!r} should route to OrgContentLibraryGlobData",
        )

    @settings(
        max_examples=100,
    )
    @given(external_key=_course_org_glob())
    def test_course_org_glob_routes_to_course_namespace(self, external_key: str) -> None:
        """
        ``course-v1:{org}+*`` routes to ``OrgCourseOverviewGlobData`` with
        NAMESPACE ``"course-v1"``.
        """
        try:
            scope = ScopeData(external_key=external_key)
        except ValueError:
            return

        self.assertEqual(
            scope.NAMESPACE,
            "course-v1",
            msg=(
                f"Glob routing crossed namespace boundary: {external_key!r} "
                f"routed to {type(scope).__name__} with "
                f"NAMESPACE={scope.NAMESPACE!r}"
            ),
        )
        self.assertIsInstance(
            scope,
            OrgCourseOverviewGlobData,
            msg=f"{external_key!r} should route to OrgCourseOverviewGlobData",
        )

    def test_platform_course_glob_routes_correctly(self) -> None:
        """``course-v1:*`` (platform glob) routes to
        ``PlatformCourseOverviewGlobData`` with NAMESPACE ``"course-v1"``."""
        scope = ScopeData(external_key="course-v1:*")
        self.assertIsInstance(scope, PlatformCourseOverviewGlobData)
        self.assertEqual(scope.NAMESPACE, "course-v1")

    def test_lib_platform_glob_raises_because_class_does_not_exist(self) -> None:
        """
        ``lib:*`` must raise ``ValueError`` - there is no
        ``PlatformContentLibraryGlobData`` in this codebase yet.
        """
        with self.assertRaises(ValueError):
            ScopeData(external_key="lib:*")


# Targeted known bad inputs
class TestScopeParserKnownBadInputs(TestCase):
    """
    Hand-crafted inputs targeting parser boundary conditions.

    These complement the Hypothesis tests with specific inputs that are
    more likely to exercise interesting edge cases. Every case must either
    raise ``ValueError`` or have the correct namespace.
    """

    _EXTERNAL_KEY_CASES: list[tuple[str, str]] = [
        ("", "empty string"),
        (":", "only separator"),
        (":lib:org:lib", "empty namespace prefix"),
        ("lib:", "empty external_key portion"),
        ("lib::", "double colon"),
        ("\x00lib:org:lib", "null byte in namespace"),
        ("lib:\x00:lib", "null byte in external_key"),
        ("lib:org:lib^extra", "caret embedded in external_key"),
        ("lib:org:lib\ninjected", "newline injection"),
        ("\nlib:org:lib", "leading newline"),
        ("lib:org:lib\r", "carriage-return suffix"),
        ("lib:" + "a" * 10_000 + ":lib", "10 k-char org name"),
        ("lib:org:lib " + "%" * 100, "percent-encoded junk suffix"),
        ("lib:org ame:lib", "space in org name"),
        ("lib:\t:lib", "tab in external_key"),
        (" lib:org:lib", "leading space in namespace"),
        ("lib:org:lib", "valid library key (positive control)"),
        ("course-v1:Org+C+R", "valid course key (positive control)"),
    ]

    def test_external_key_known_bad_inputs(self) -> None:
        """
        Every known bad external_key either raises ``ValueError`` or
        or has the correct namespace.
        """
        for external_key, desc in self._EXTERNAL_KEY_CASES:
            with self.subTest(desc=desc, external_key=external_key[:80]):
                try:
                    scope = ScopeData(external_key=external_key)
                except ValueError:
                    continue  # clean rejection
                except Exception as exc:  # pylint: disable=broad-except
                    self.fail(f"{desc!r}: unexpected {type(exc).__name__}: {exc}")
                else:
                    # Parsing succeeded, verify namespace
                    if external_key == "*":
                        expected_ns = "global"
                    elif EXTERNAL_KEY_SEPARATOR in external_key:
                        expected_ns = external_key.split(EXTERNAL_KEY_SEPARATOR, 1)[0]
                    else:
                        self.fail(f"{desc!r}: parsing succeeded but no ':' in input")
                    self.assertEqual(
                        scope.NAMESPACE,
                        expected_ns,
                        msg=f"{desc!r}: NAMESPACE should be {expected_ns!r}",
                    )

    _NAMESPACED_KEY_CASES: list[tuple[str, str]] = [
        ("^", "only caret"),
        ("^something", "empty namespace (caret first)"),
        ("something^", "empty external_key (caret last)"),
        ("\x00^something", "null byte in namespace"),
        ("lib^\x00lib:org:lib", "null byte in external_key portion"),
        ("lib^\nlib:org:lib", "newline in external_key portion"),
        ("lib^lib:org:lib\ninjected", "newline injection after valid key"),
        ("lib^lib:org:lib^extra", "extra caret in external_key"),
        ("lib^" + "a" * 10_000, "10 k-char external_key"),
        ("lib^lib:org:lib", "valid lib namespaced_key (positive control)"),
        ("course-v1^course-v1:Org+C+R", "valid course namespaced_key (positive control)"),
    ]

    def test_namespaced_key_known_bad_inputs(self) -> None:
        """
        Every known bad namespaced_key either raises ``ValueError`` or
        produces a scope whose NAMESPACE matches the prefix before ``"^"``.

        Note: inputs with an *unknown* namespace prefix (e.g., random text
        before ``^``) may succeed due to the fallback, in which case
        ``scope.NAMESPACE`` will be ``"global"`` rather than the declared
        prefix. This test documents that case without failing on it
        (see ``TestScopeParserFindings``).
        """
        for namespaced_key, desc in self._NAMESPACED_KEY_CASES:
            with self.subTest(desc=desc, namespaced_key=namespaced_key[:80]):
                try:
                    scope = ScopeData(namespaced_key=namespaced_key)
                except ValueError:
                    continue  # clean rejection
                except Exception as exc:  # pylint: disable=broad-except
                    self.fail(f"{desc!r}: unexpected {type(exc).__name__}: {exc}")
                else:
                    # Parsing succeeded - check that namespace is one of the
                    # expected values: either the declared prefix (correct) or
                    # "global" (fallback for unknown namespaces).
                    declared_prefix = namespaced_key.split(AUTHZ_POLICY_ATTRIBUTES_SEPARATOR, 1)[0]
                    self.assertIn(
                        scope.NAMESPACE,
                        {declared_prefix, "global"},
                        msg=(
                            f"{desc!r}: NAMESPACE={scope.NAMESPACE!r} is neither "
                            f"the declared prefix {declared_prefix!r} nor the "
                            f"known fallback 'global'."
                        ),
                    )

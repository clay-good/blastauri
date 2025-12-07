"""Integration tests for breaking change detection with mocked API responses."""



from blastauri.analysis.known_breaking_changes import (
    KNOWN_BREAKING_CHANGES,
    get_all_packages_with_known_changes,
    get_known_breaking_changes,
)
from blastauri.core.models import BreakingChangeType, Ecosystem


class TestKnownBreakingChangesDatabase:
    """Test the curated breaking changes database."""

    def test_database_not_empty(self) -> None:
        """Test that we have breaking changes in the database."""
        assert len(KNOWN_BREAKING_CHANGES) > 0

    def test_database_has_npm_packages(self) -> None:
        """Test that database includes NPM packages."""
        npm_packages = [
            kbc for kbc in KNOWN_BREAKING_CHANGES if kbc.ecosystem == Ecosystem.NPM
        ]
        assert len(npm_packages) > 0

        # Check for some expected popular packages
        npm_names = {kbc.package for kbc in npm_packages}
        assert "lodash" in npm_names
        assert "express" in npm_names
        assert "react" in npm_names

    def test_database_has_pypi_packages(self) -> None:
        """Test that database includes PyPI packages."""
        pypi_packages = [
            kbc for kbc in KNOWN_BREAKING_CHANGES if kbc.ecosystem == Ecosystem.PYPI
        ]
        assert len(pypi_packages) > 0

        # Check for some expected popular packages
        pypi_names = {kbc.package for kbc in pypi_packages}
        assert "django" in pypi_names
        assert "pydantic" in pypi_names
        assert "flask" in pypi_names

    def test_all_changes_have_required_fields(self) -> None:
        """Test that all breaking changes have required fields."""
        for kbc in KNOWN_BREAKING_CHANGES:
            assert kbc.ecosystem is not None
            assert kbc.package is not None
            assert kbc.from_version is not None
            assert kbc.to_version is not None
            assert kbc.change is not None
            assert kbc.change.change_type is not None
            assert kbc.change.description is not None
            assert kbc.change.source == "known_breaking_changes"

    def test_breaking_changes_have_migration_guides(self) -> None:
        """Test that breaking changes have migration guides."""
        for kbc in KNOWN_BREAKING_CHANGES:
            # All curated entries should have migration guides
            assert kbc.change.migration_guide is not None
            assert len(kbc.change.migration_guide) > 0


class TestGetKnownBreakingChanges:
    """Test the get_known_breaking_changes function."""

    def test_get_pydantic_breaking_changes(self) -> None:
        """Test getting breaking changes for pydantic 1.x -> 2.x."""
        changes = get_known_breaking_changes(
            ecosystem=Ecosystem.PYPI,
            package_name="pydantic",
            from_version="1.10.0",
            to_version="2.0.0",
        )

        assert len(changes) > 0

        # Check for expected changes
        descriptions = [c.description for c in changes]
        assert any("dict()" in d or "model_dump" in d for d in descriptions)
        assert any("json()" in d or "model_dump_json" in d for d in descriptions)

    def test_get_react_breaking_changes(self) -> None:
        """Test getting breaking changes for React 17 -> 18."""
        changes = get_known_breaking_changes(
            ecosystem=Ecosystem.NPM,
            package_name="react",
            from_version="17.0.2",
            to_version="18.0.0",
        )

        assert len(changes) > 0

        # Check for createRoot change
        descriptions = [c.description for c in changes]
        assert any("createRoot" in d or "ReactDOM.render" in d for d in descriptions)

    def test_no_changes_for_minor_upgrade(self) -> None:
        """Test that minor upgrades don't return breaking changes."""
        changes = get_known_breaking_changes(
            ecosystem=Ecosystem.PYPI,
            package_name="pydantic",
            from_version="1.9.0",
            to_version="1.10.0",
        )

        # Minor version upgrades typically don't have breaking changes
        # Our database records major version changes
        assert len(changes) == 0

    def test_no_changes_for_unknown_package(self) -> None:
        """Test that unknown packages return empty list."""
        changes = get_known_breaking_changes(
            ecosystem=Ecosystem.PYPI,
            package_name="unknown-package-xyz",
            from_version="1.0.0",
            to_version="2.0.0",
        )

        assert len(changes) == 0

    def test_package_name_normalization(self) -> None:
        """Test that package names are normalized correctly."""
        # Test with different casings and separators
        changes1 = get_known_breaking_changes(
            ecosystem=Ecosystem.PYPI,
            package_name="pydantic",
            from_version="1.0.0",
            to_version="2.0.0",
        )

        changes2 = get_known_breaking_changes(
            ecosystem=Ecosystem.PYPI,
            package_name="Pydantic",
            from_version="1.0.0",
            to_version="2.0.0",
        )

        assert len(changes1) == len(changes2)


class TestGetAllPackagesWithKnownChanges:
    """Test the get_all_packages_with_known_changes function."""

    def test_returns_dict_by_ecosystem(self) -> None:
        """Test that function returns packages grouped by ecosystem."""
        packages = get_all_packages_with_known_changes()

        assert isinstance(packages, dict)
        assert Ecosystem.NPM in packages
        assert Ecosystem.PYPI in packages

    def test_packages_are_sorted(self) -> None:
        """Test that package lists are sorted."""
        packages = get_all_packages_with_known_changes()

        for ecosystem, pkg_list in packages.items():
            assert pkg_list == sorted(pkg_list)


class TestBreakingChangeTypes:
    """Test different breaking change types in the database."""

    def test_removed_function_changes_exist(self) -> None:
        """Test that we have removed function changes."""
        removed_func = [
            kbc
            for kbc in KNOWN_BREAKING_CHANGES
            if kbc.change.change_type == BreakingChangeType.REMOVED_FUNCTION
        ]
        assert len(removed_func) > 0

    def test_changed_signature_changes_exist(self) -> None:
        """Test that we have changed signature changes."""
        changed_sig = [
            kbc
            for kbc in KNOWN_BREAKING_CHANGES
            if kbc.change.change_type == BreakingChangeType.CHANGED_SIGNATURE
        ]
        assert len(changed_sig) > 0

    def test_changed_behavior_changes_exist(self) -> None:
        """Test that we have changed behavior changes."""
        changed_behavior = [
            kbc
            for kbc in KNOWN_BREAKING_CHANGES
            if kbc.change.change_type == BreakingChangeType.CHANGED_BEHAVIOR
        ]
        assert len(changed_behavior) > 0

    def test_changed_default_changes_exist(self) -> None:
        """Test that we have changed default changes."""
        changed_default = [
            kbc
            for kbc in KNOWN_BREAKING_CHANGES
            if kbc.change.change_type == BreakingChangeType.CHANGED_DEFAULT
        ]
        assert len(changed_default) > 0


class TestSpecificPackageChanges:
    """Test specific package breaking changes in detail."""

    def test_django_url_removal(self) -> None:
        """Test Django url() function removal is documented."""
        changes = get_known_breaking_changes(
            ecosystem=Ecosystem.PYPI,
            package_name="django",
            from_version="3.2",
            to_version="4.0",
        )

        # Find the url() removal change
        url_change = next(
            (c for c in changes if "url()" in c.description.lower()), None
        )

        assert url_change is not None
        assert url_change.change_type == BreakingChangeType.REMOVED_FUNCTION
        assert "path" in url_change.new_api or "re_path" in url_change.new_api

    def test_lodash_pluck_removal(self) -> None:
        """Test lodash _.pluck removal is documented."""
        changes = get_known_breaking_changes(
            ecosystem=Ecosystem.NPM,
            package_name="lodash",
            from_version="4.17.21",
            to_version="5.0.0",
        )

        # Find the pluck removal
        pluck_change = next((c for c in changes if "pluck" in c.description.lower()), None)

        assert pluck_change is not None
        assert pluck_change.change_type == BreakingChangeType.REMOVED_FUNCTION

    def test_webpack_polyfills_removal(self) -> None:
        """Test webpack Node.js polyfills removal is documented."""
        changes = get_known_breaking_changes(
            ecosystem=Ecosystem.NPM,
            package_name="webpack",
            from_version="4.46.0",
            to_version="5.0.0",
        )

        # Find the polyfills removal
        polyfill_change = next(
            (c for c in changes if "polyfill" in c.description.lower()), None
        )

        assert polyfill_change is not None
        assert polyfill_change.change_type == BreakingChangeType.REMOVED_FUNCTION

    def test_sqlalchemy_2_changes(self) -> None:
        """Test SQLAlchemy 2.0 changes are documented."""
        changes = get_known_breaking_changes(
            ecosystem=Ecosystem.PYPI,
            package_name="sqlalchemy",
            from_version="1.4.0",
            to_version="2.0.0",
        )

        assert len(changes) > 0

        # Check for Query.get() change
        get_change = next(
            (c for c in changes if "get()" in c.description.lower() or "session.get" in c.description.lower()),
            None,
        )
        assert get_change is not None


class TestBreakingChangeModel:
    """Test the BreakingChange model structure."""

    def test_breaking_change_has_old_and_new_api(self) -> None:
        """Test that breaking changes document old and new API."""
        # Most curated changes should have old_api and new_api
        with_api_docs = [
            kbc
            for kbc in KNOWN_BREAKING_CHANGES
            if kbc.change.old_api and kbc.change.new_api
        ]

        # At least 50% should have API documentation
        assert len(with_api_docs) >= len(KNOWN_BREAKING_CHANGES) // 2

    def test_breaking_change_source_is_correct(self) -> None:
        """Test that all known changes have correct source."""
        for kbc in KNOWN_BREAKING_CHANGES:
            assert kbc.change.source == "known_breaking_changes"


class TestVersionParsing:
    """Test version parsing in breaking change detection."""

    def test_handles_various_version_formats(self) -> None:
        """Test that various version formats are handled."""
        # Test with different version formats
        test_cases = [
            ("1.0.0", "2.0.0"),
            ("1.0", "2.0"),
            ("1", "2"),
            ("v1.0.0", "v2.0.0"),
        ]

        for from_v, to_v in test_cases:
            # Should not raise
            changes = get_known_breaking_changes(
                ecosystem=Ecosystem.PYPI,
                package_name="pydantic",
                from_version=from_v,
                to_version=to_v,
            )
            # Just verify it returns a list without error
            assert isinstance(changes, list)

    def test_handles_prerelease_versions(self) -> None:
        """Test that prerelease versions are handled."""
        # Test with prerelease versions
        changes = get_known_breaking_changes(
            ecosystem=Ecosystem.PYPI,
            package_name="pydantic",
            from_version="1.10.0-rc1",
            to_version="2.0.0-beta1",
        )

        # Should return results (version parsing should handle this)
        assert isinstance(changes, list)


class TestCoverageOfPopularPackages:
    """Test that popular packages are covered in the database."""

    def test_npm_popular_packages_covered(self) -> None:
        """Test that popular NPM packages are in the database."""
        packages = get_all_packages_with_known_changes()
        npm_packages = packages.get(Ecosystem.NPM, [])

        popular_npm = ["react", "lodash", "express", "webpack", "typescript", "next"]

        covered = [pkg for pkg in popular_npm if pkg in npm_packages]
        # At least 4 of 6 popular packages should be covered
        assert len(covered) >= 4

    def test_pypi_popular_packages_covered(self) -> None:
        """Test that popular PyPI packages are in the database."""
        packages = get_all_packages_with_known_changes()
        pypi_packages = packages.get(Ecosystem.PYPI, [])

        popular_pypi = ["django", "flask", "pydantic", "sqlalchemy", "pytest", "numpy"]

        covered = [pkg for pkg in popular_pypi if pkg in pypi_packages]
        # At least 4 of 6 popular packages should be covered
        assert len(covered) >= 4

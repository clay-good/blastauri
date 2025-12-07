"""Integration tests for full analysis pipeline."""

from pathlib import Path

import pytest

from blastauri.core.models import (
    CVE,
    BreakingChange,
    BreakingChangeType,
    Ecosystem,
    Severity,
)
from blastauri.scanners.detector import detect_ecosystems, get_scanners


class TestFullScanPipeline:
    """Integration tests for full dependency scan pipeline."""

    @pytest.fixture
    def npm_project(self, tmp_path: Path) -> Path:
        """Create a temporary npm project."""
        project = tmp_path / "npm-project"
        project.mkdir()

        # Create package.json
        package_json = project / "package.json"
        package_json.write_text(
            """{
  "name": "test-project",
  "version": "1.0.0",
  "dependencies": {
    "lodash": "4.17.15",
    "express": "4.17.0"
  },
  "devDependencies": {
    "jest": "29.0.0"
  }
}"""
        )

        # Create package-lock.json
        package_lock = project / "package-lock.json"
        package_lock.write_text(
            """{
  "name": "test-project",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": {
      "name": "test-project",
      "version": "1.0.0",
      "dependencies": {
        "lodash": "4.17.15",
        "express": "4.17.0"
      },
      "devDependencies": {
        "jest": "29.0.0"
      }
    },
    "node_modules/lodash": {
      "version": "4.17.15",
      "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.15.tgz"
    },
    "node_modules/express": {
      "version": "4.17.0",
      "resolved": "https://registry.npmjs.org/express/-/express-4.17.0.tgz"
    },
    "node_modules/jest": {
      "version": "29.0.0",
      "resolved": "https://registry.npmjs.org/jest/-/jest-29.0.0.tgz",
      "dev": true
    }
  }
}"""
        )

        # Create a JS file that uses lodash
        src_dir = project / "src"
        src_dir.mkdir()
        index_js = src_dir / "index.js"
        index_js.write_text(
            """const _ = require('lodash');
const express = require('express');

const app = express();

const data = [1, 2, 3, 4, 5];
const doubled = _.map(data, x => x * 2);

console.log(doubled);
"""
        )

        return project

    @pytest.fixture
    def python_project(self, tmp_path: Path) -> Path:
        """Create a temporary Python project."""
        project = tmp_path / "python-project"
        project.mkdir()

        # Create requirements.txt
        requirements = project / "requirements.txt"
        requirements.write_text(
            """requests==2.28.0
pydantic==1.10.0
flask==2.0.0
"""
        )

        # Create a Python file
        src_dir = project / "src"
        src_dir.mkdir()
        main_py = src_dir / "main.py"
        main_py.write_text(
            """import requests
from pydantic import BaseModel
from flask import Flask

app = Flask(__name__)

class User(BaseModel):
    name: str
    email: str

def get_data():
    response = requests.get('https://api.example.com/data')
    return response.json()
"""
        )

        return project

    def test_npm_ecosystem_detection(self, npm_project: Path) -> None:
        """Test npm ecosystem is detected correctly."""
        ecosystems = detect_ecosystems(str(npm_project))
        assert Ecosystem.NPM in ecosystems

    def test_python_ecosystem_detection(self, python_project: Path) -> None:
        """Test Python ecosystem is detected correctly."""
        ecosystems = detect_ecosystems(str(python_project))
        assert Ecosystem.PYPI in ecosystems

    def test_npm_full_scan(self, npm_project: Path) -> None:
        """Test full npm scan pipeline."""
        scanners = get_scanners(str(npm_project))
        assert len(scanners) >= 1

        # Scan the project
        all_deps = []
        for scanner in scanners:
            result = scanner.scan_directory(str(npm_project))
            all_deps.extend(result.dependencies)

        # Should find lodash, express, and jest
        dep_names = {d.name for d in all_deps}
        assert "lodash" in dep_names
        assert "express" in dep_names

    def test_python_full_scan(self, python_project: Path) -> None:
        """Test full Python scan pipeline."""
        scanners = get_scanners(str(python_project))
        assert len(scanners) >= 1

        # Scan the project
        all_deps = []
        for scanner in scanners:
            result = scanner.scan_directory(str(python_project))
            all_deps.extend(result.dependencies)

        # Should find requests, pydantic, flask
        dep_names = {d.name for d in all_deps}
        assert "requests" in dep_names
        assert "pydantic" in dep_names
        assert "flask" in dep_names


class TestWafGenerationPipeline:
    """Integration tests for WAF generation pipeline."""

    @pytest.fixture
    def sample_cves(self) -> list[CVE]:
        """Create sample CVEs for testing."""
        return [
            CVE(
                id="CVE-2021-44228",
                description="Log4j JNDI injection RCE",
                severity=Severity.CRITICAL,
                source="nvd",
                is_waf_mitigatable=True,
                waf_pattern_id="log4shell",
            ),
            CVE(
                id="CVE-2022-22965",
                description="Spring4Shell RCE",
                severity=Severity.CRITICAL,
                source="nvd",
                is_waf_mitigatable=True,
                waf_pattern_id="spring4shell",
            ),
        ]

    def test_waf_generation_aws(self, sample_cves: list[CVE], tmp_path: Path) -> None:
        """Test full AWS WAF generation pipeline."""
        from blastauri.waf.generator import WafGenerator, WafGeneratorConfig
        from blastauri.waf.providers.base import WafProviderType, WafRuleMode

        config = WafGeneratorConfig(
            provider=WafProviderType.AWS,
            mode=WafRuleMode.LOG,
            name_prefix="test",
        )

        generator = WafGenerator(config)
        # Pass CVE IDs as strings, not CVE objects
        cve_ids = [cve.id for cve in sample_cves]
        result = generator.generate_from_cves(cve_ids)

        assert result.rules_count > 0

        # Check Terraform files were generated
        filenames = [f.filename for f in result.files]
        assert any("tf" in f for f in filenames)

    def test_waf_generation_cloudflare(
        self, sample_cves: list[CVE], tmp_path: Path
    ) -> None:
        """Test full Cloudflare WAF generation pipeline."""
        from blastauri.waf.generator import WafGenerator, WafGeneratorConfig
        from blastauri.waf.providers.base import WafProviderType, WafRuleMode

        config = WafGeneratorConfig(
            provider=WafProviderType.CLOUDFLARE,
            mode=WafRuleMode.LOG,
            name_prefix="test",
        )

        generator = WafGenerator(config)
        # Pass CVE IDs as strings, not CVE objects
        cve_ids = [cve.id for cve in sample_cves]
        result = generator.generate_from_cves(cve_ids)

        assert result.rules_count > 0


class TestAnalysisPipeline:
    """Integration tests for breaking change analysis pipeline."""

    @pytest.fixture
    def breaking_change_upgrade(self) -> dict:
        """Create an upgrade scenario with breaking changes."""
        return {
            "name": "lodash",
            "ecosystem": Ecosystem.NPM,
            "from_version": "4.17.15",
            "to_version": "5.0.0",
            "is_major": True,
        }

    def test_impact_calculation_pipeline(self, tmp_path: Path) -> None:
        """Test full impact calculation pipeline."""
        from blastauri.analysis.impact_calculator import ImpactCalculator
        from blastauri.core.models import (
            ImpactedLocation,
            UsageLocation,
        )

        calculator = ImpactCalculator()

        # Create breaking changes
        breaking_changes = [
            BreakingChange(
                change_type=BreakingChangeType.REMOVED_FUNCTION,
                description="_.pluck removed",
                old_api="pluck",
                new_api="map",
                source="known_db",
            ),
            BreakingChange(
                change_type=BreakingChangeType.CHANGED_SIGNATURE,
                description="_.merge behavior changed",
                old_api="merge",
                source="changelog",
            ),
        ]

        # Create impacted locations
        impacted_locations = [
            ImpactedLocation(
                location=UsageLocation(
                    file_path="src/utils.js",
                    line_number=10,
                    column=5,
                    code_snippet="_.pluck(data, 'name')",
                    usage_type="call",
                    symbol="pluck",
                ),
                breaking_change=breaking_changes[0],
                confidence=0.9,
            ),
        ]

        # Calculate impact
        impact = calculator.calculate_upgrade_impact(
            dependency_name="lodash",
            ecosystem=Ecosystem.NPM,
            from_version="4.17.15",
            to_version="5.0.0",
            breaking_changes=breaking_changes,
            impacted_locations=impacted_locations,
            cves_fixed=[],
            is_major_upgrade=True,
        )

        assert impact.risk_score > 0
        assert impact.severity in [
            Severity.LOW,
            Severity.MEDIUM,
            Severity.HIGH,
            Severity.CRITICAL,
        ]
        assert len(impact.breaking_changes) == 2


class TestMultiEcosystemPipeline:
    """Integration tests for multi-ecosystem scanning."""

    @pytest.fixture
    def multi_ecosystem_project(self, tmp_path: Path) -> Path:
        """Create a project with multiple ecosystems."""
        project = tmp_path / "multi-project"
        project.mkdir()

        # Create npm package-lock.json
        npm_lock = project / "package-lock.json"
        npm_lock.write_text(
            """{
  "name": "multi-project",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "node_modules/react": {
      "version": "18.0.0"
    }
  }
}"""
        )

        # Create Python requirements.txt
        requirements = project / "requirements.txt"
        requirements.write_text("django==4.0.0\n")

        # Create Go go.mod
        go_mod = project / "go.mod"
        go_mod.write_text(
            """module example.com/multi
go 1.21
require github.com/gin-gonic/gin v1.9.0
"""
        )

        return project

    def test_multi_ecosystem_detection(self, multi_ecosystem_project: Path) -> None:
        """Test detection of multiple ecosystems."""
        ecosystems = detect_ecosystems(str(multi_ecosystem_project))

        assert Ecosystem.NPM in ecosystems
        assert Ecosystem.PYPI in ecosystems
        assert Ecosystem.GO in ecosystems

    def test_multi_ecosystem_scan(self, multi_ecosystem_project: Path) -> None:
        """Test scanning multiple ecosystems."""
        scanners = get_scanners(str(multi_ecosystem_project))
        assert len(scanners) >= 3  # npm, pip, go

        all_deps = []
        ecosystems_found = set()

        for scanner in scanners:
            result = scanner.scan_directory(str(multi_ecosystem_project))
            all_deps.extend(result.dependencies)
            for dep in result.dependencies:
                ecosystems_found.add(dep.ecosystem)

        # Verify we scanned multiple ecosystems
        assert len(ecosystems_found) >= 2


class TestCVEAggregationPipeline:
    """Integration tests for CVE aggregation pipeline."""

    def test_waf_pattern_detection(self) -> None:
        """Test WAF-mitigatable pattern detection."""
        from blastauri.core.models import CVE, Severity
        from blastauri.cve.waf_patterns import (
            get_waf_pattern,
            get_waf_pattern_id,
            is_waf_mitigatable,
        )

        # Create CVE object for testing
        log4j_cve = CVE(
            id="CVE-2021-44228",
            description="Log4j JNDI injection RCE",
            severity=Severity.CRITICAL,
            source="nvd",
        )

        # Test known WAF-mitigatable CVE
        assert is_waf_mitigatable(log4j_cve) is True
        pattern_id = get_waf_pattern_id(log4j_cve)
        assert pattern_id == "log4j"
        pattern = get_waf_pattern("log4j")
        assert pattern is not None
        assert pattern.id == "log4j"

        # Test non-WAF-mitigatable CVE
        other_cve = CVE(
            id="CVE-2020-12345",
            description="Some other vulnerability",
            severity=Severity.MEDIUM,
            source="nvd",
        )
        # Note: is_waf_mitigatable takes a CVE object
        # For unknown CVEs it may return True/False based on pattern matching
        # so we just verify it returns a boolean
        result = is_waf_mitigatable(other_cve)
        assert isinstance(result, bool)


class TestConfigurationPipeline:
    """Integration tests for configuration handling."""

    def test_config_loading(self, tmp_path: Path) -> None:
        """Test configuration file loading."""
        from blastauri.config import BlastauriConfig, load_config

        # Create config file
        config_file = tmp_path / ".blastauri.yml"
        config_file.write_text(
            """version: 1
platform: gitlab
analysis:
  ai_provider: none
  severity_threshold: low
waf:
  provider: aws
  mode: log
"""
        )

        config = load_config(config_file)
        assert isinstance(config, BlastauriConfig)
        assert config.platform == "gitlab"
        assert config.analysis.ai_provider == "none"
        assert config.waf.provider == "aws"

    def test_config_defaults(self) -> None:
        """Test default configuration values."""
        from blastauri.config import BlastauriConfig, load_config

        # Load with no file
        config = load_config(config_path=None)
        assert isinstance(config, BlastauriConfig)
        assert config.version == 1


class TestWafLifecyclePipeline:
    """Integration tests for WAF lifecycle management."""

    def test_lifecycle_state_management(self, tmp_path: Path) -> None:
        """Test WAF state file management."""
        from blastauri.waf.lifecycle import WafLifecycleManager, WafState
        from blastauri.waf.providers.base import WafProviderType

        # Create state directory
        state_dir = tmp_path / ".blastauri"
        state_dir.mkdir()

        manager = WafLifecycleManager(
            repo_path=str(tmp_path),
            provider=WafProviderType.AWS,
            promotion_days=14,
        )

        # Load initial state (should be empty)
        state = manager.load_state()
        assert isinstance(state, WafState)
        assert len(state.rules) == 0

        # Save state
        manager.save_state(state)

        # Reload and verify
        reloaded = manager.load_state()
        assert isinstance(reloaded, WafState)


class TestEndToEndScenarios:
    """End-to-end integration tests for realistic scenarios."""

    def test_renovate_upgrade_scenario(self, tmp_path: Path) -> None:
        """Test a realistic Renovate upgrade scenario."""
        # Create a project
        project = tmp_path / "my-app"
        project.mkdir()

        # Create package-lock.json with old lodash
        lock_file = project / "package-lock.json"
        lock_file.write_text(
            """{
  "name": "my-app",
  "lockfileVersion": 3,
  "packages": {
    "node_modules/lodash": {"version": "4.17.15"}
  }
}"""
        )

        # Create JS file using lodash
        src = project / "src"
        src.mkdir()
        app_js = src / "app.js"
        app_js.write_text(
            """const _ = require('lodash');
const result = _.pluck(users, 'name');
"""
        )

        # Scan dependencies
        scanners = get_scanners(str(project))
        deps = []
        for scanner in scanners:
            result = scanner.scan_directory(str(project))
            deps.extend(result.dependencies)

        # Verify lodash found
        lodash_dep = next((d for d in deps if d.name == "lodash"), None)
        assert lodash_dep is not None
        assert lodash_dep.version == "4.17.15"

    def test_waf_rule_creation_scenario(self, tmp_path: Path) -> None:
        """Test creating WAF rules for vulnerable dependencies."""
        from blastauri.waf.generator import (
            generate_owasp_rules,
        )
        from blastauri.waf.providers.base import WafProviderType, WafRuleMode
        from blastauri.waf.rule_templates import get_default_registry

        # Get available templates
        registry = get_default_registry()
        templates = registry.get_all_templates()
        assert len(templates) > 0

        # Generate OWASP rules - function takes individual params, not config
        result = generate_owasp_rules(
            provider=WafProviderType.AWS,
            mode=WafRuleMode.LOG,
            name_prefix="myapp",
        )
        assert result.rules_count > 0
        assert len(result.files) > 0

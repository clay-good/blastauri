"""Tests for WAF lifecycle management module."""

import json
import tempfile
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from blastauri.core.models import Dependency, Ecosystem, Severity
from blastauri.core.waf_orchestrator import (
    WafSyncConfig,
    WafSyncOrchestrator,
    WafSyncResult,
)
from blastauri.git.mr_creator import (
    FileChange,
    MrCreationConfig,
    MrCreationResult,
    MrCreator,
    WafMrCreator,
)
from blastauri.waf.lifecycle import (
    LifecycleAnalysis,
    LifecycleChange,
    RuleTrigger,
    WafLifecycleManager,
    WafRuleState,
    WafState,
)
from blastauri.waf.providers.base import WafProviderType, WafRuleMode


class TestRuleTrigger:
    """Tests for RuleTrigger dataclass."""

    def test_create_trigger(self) -> None:
        """Test creating a rule trigger."""
        trigger = RuleTrigger(
            ecosystem="npm",
            package="lodash",
            version="4.17.20",
            detected_at="2024-01-15T00:00:00Z",
        )

        assert trigger.ecosystem == "npm"
        assert trigger.package == "lodash"
        assert trigger.version == "4.17.20"


class TestWafRuleState:
    """Tests for WafRuleState dataclass."""

    def test_create_rule_state(self) -> None:
        """Test creating a rule state."""
        trigger = RuleTrigger(
            ecosystem="maven",
            package="log4j-core",
            version="2.14.0",
            detected_at="2024-01-15T00:00:00Z",
        )

        state = WafRuleState(
            rule_id="blastauri-log4j",
            cve_ids=["CVE-2021-44228"],
            created_at="2024-01-15T00:00:00Z",
            mode="log",
            provider="aws",
            triggered_by=trigger,
            status="active",
        )

        assert state.rule_id == "blastauri-log4j"
        assert "CVE-2021-44228" in state.cve_ids
        assert state.mode == "log"
        assert state.status == "active"

    def test_to_dict(self) -> None:
        """Test converting rule state to dictionary."""
        trigger = RuleTrigger(
            ecosystem="maven",
            package="log4j-core",
            version="2.14.0",
            detected_at="2024-01-15T00:00:00Z",
        )

        state = WafRuleState(
            rule_id="blastauri-log4j",
            cve_ids=["CVE-2021-44228"],
            created_at="2024-01-15T00:00:00Z",
            mode="log",
            provider="aws",
            triggered_by=trigger,
            status="active",
        )

        data = state.to_dict()

        assert data["rule_id"] == "blastauri-log4j"
        assert data["cve_ids"] == ["CVE-2021-44228"]
        assert data["triggered_by"]["package"] == "log4j-core"

    def test_from_dict(self) -> None:
        """Test creating rule state from dictionary."""
        data = {
            "rule_id": "blastauri-log4j",
            "cve_ids": ["CVE-2021-44228"],
            "created_at": "2024-01-15T00:00:00Z",
            "mode": "log",
            "provider": "aws",
            "triggered_by": {
                "ecosystem": "maven",
                "package": "log4j-core",
                "version": "2.14.0",
                "detected_at": "2024-01-15T00:00:00Z",
            },
            "status": "active",
        }

        state = WafRuleState.from_dict(data)

        assert state.rule_id == "blastauri-log4j"
        assert state.triggered_by.package == "log4j-core"


class TestWafState:
    """Tests for WafState dataclass."""

    def test_empty_state(self) -> None:
        """Test creating empty state."""
        state = WafState.empty("aws")

        assert state.version == 1
        assert state.provider == "aws"
        assert len(state.rules) == 0

    def test_get_active_rules(self) -> None:
        """Test getting active rules."""
        trigger = RuleTrigger(
            ecosystem="maven",
            package="log4j-core",
            version="2.14.0",
            detected_at="2024-01-15T00:00:00Z",
        )

        active_rule = WafRuleState(
            rule_id="active-rule",
            cve_ids=["CVE-2021-44228"],
            created_at="2024-01-15T00:00:00Z",
            mode="log",
            provider="aws",
            triggered_by=trigger,
            status="active",
        )

        obsolete_rule = WafRuleState(
            rule_id="obsolete-rule",
            cve_ids=["CVE-2020-1234"],
            created_at="2024-01-15T00:00:00Z",
            mode="log",
            provider="aws",
            triggered_by=trigger,
            status="obsolete",
        )

        state = WafState(
            version=1,
            generated_at="2024-01-15T00:00:00Z",
            rules=[active_rule, obsolete_rule],
        )

        active = state.get_active_rules()

        assert len(active) == 1
        assert active[0].rule_id == "active-rule"

    def test_get_rule_by_id(self) -> None:
        """Test getting rule by ID."""
        trigger = RuleTrigger(
            ecosystem="maven",
            package="log4j-core",
            version="2.14.0",
            detected_at="2024-01-15T00:00:00Z",
        )

        rule = WafRuleState(
            rule_id="test-rule",
            cve_ids=["CVE-2021-44228"],
            created_at="2024-01-15T00:00:00Z",
            mode="log",
            provider="aws",
            triggered_by=trigger,
            status="active",
        )

        state = WafState(
            version=1,
            generated_at="2024-01-15T00:00:00Z",
            rules=[rule],
        )

        found = state.get_rule_by_id("test-rule")
        not_found = state.get_rule_by_id("nonexistent")

        assert found is not None
        assert found.rule_id == "test-rule"
        assert not_found is None

    def test_to_dict_and_from_dict(self) -> None:
        """Test round-trip serialization."""
        trigger = RuleTrigger(
            ecosystem="maven",
            package="log4j-core",
            version="2.14.0",
            detected_at="2024-01-15T00:00:00Z",
        )

        rule = WafRuleState(
            rule_id="test-rule",
            cve_ids=["CVE-2021-44228"],
            created_at="2024-01-15T00:00:00Z",
            mode="log",
            provider="aws",
            triggered_by=trigger,
            status="active",
        )

        original = WafState(
            version=1,
            generated_at="2024-01-15T00:00:00Z",
            rules=[rule],
        )

        data = original.to_dict()
        restored = WafState.from_dict(data)

        assert restored.version == original.version
        assert len(restored.rules) == len(original.rules)
        assert restored.rules[0].rule_id == original.rules[0].rule_id


class TestWafLifecycleManager:
    """Tests for WafLifecycleManager."""

    @pytest.fixture
    def temp_repo(self) -> Path:
        """Create temporary repository directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def manager(self, temp_repo: Path) -> WafLifecycleManager:
        """Create lifecycle manager instance."""
        return WafLifecycleManager(
            repo_path=str(temp_repo),
            provider=WafProviderType.AWS,
            promotion_days=14,
        )

    def test_load_empty_state(self, manager: WafLifecycleManager) -> None:
        """Test loading state when no file exists."""
        state = manager.load_state()

        assert state.version == 1
        assert len(state.rules) == 0

    def test_save_and_load_state(
        self, manager: WafLifecycleManager, temp_repo: Path
    ) -> None:
        """Test saving and loading state."""
        trigger = RuleTrigger(
            ecosystem="maven",
            package="log4j-core",
            version="2.14.0",
            detected_at="2024-01-15T00:00:00Z",
        )

        rule = WafRuleState(
            rule_id="test-rule",
            cve_ids=["CVE-2021-44228"],
            created_at="2024-01-15T00:00:00Z",
            mode="log",
            provider="aws",
            triggered_by=trigger,
            status="active",
        )

        state = WafState(
            version=1,
            generated_at="2024-01-15T00:00:00Z",
            rules=[rule],
        )

        manager.save_state(state)

        # Verify file exists
        assert manager.state_file_path.exists()

        # Load and verify
        loaded = manager.load_state()
        assert len(loaded.rules) == 1
        assert loaded.rules[0].rule_id == "test-rule"

    def test_find_promotion_candidates(
        self, manager: WafLifecycleManager
    ) -> None:
        """Test finding promotion candidates."""
        old_date = (datetime.utcnow() - timedelta(days=30)).isoformat() + "Z"
        recent_date = (datetime.utcnow() - timedelta(days=5)).isoformat() + "Z"

        trigger = RuleTrigger(
            ecosystem="maven",
            package="log4j-core",
            version="2.14.0",
            detected_at="2024-01-15T00:00:00Z",
        )

        old_rule = WafRuleState(
            rule_id="old-rule",
            cve_ids=["CVE-2021-44228"],
            created_at=old_date,
            mode="log",
            provider="aws",
            triggered_by=trigger,
            status="active",
        )

        recent_rule = WafRuleState(
            rule_id="recent-rule",
            cve_ids=["CVE-2022-22965"],
            created_at=recent_date,
            mode="log",
            provider="aws",
            triggered_by=trigger,
            status="active",
        )

        block_rule = WafRuleState(
            rule_id="block-rule",
            cve_ids=["CVE-2020-1234"],
            created_at=old_date,
            mode="block",
            provider="aws",
            triggered_by=trigger,
            status="active",
        )

        state = WafState(
            version=1,
            generated_at="2024-01-15T00:00:00Z",
            rules=[old_rule, recent_rule, block_rule],
        )

        candidates = manager.find_promotion_candidates(state)

        assert len(candidates) == 1
        assert candidates[0].rule_id == "old-rule"

    def test_promote_rule(self, manager: WafLifecycleManager) -> None:
        """Test promoting a rule."""
        trigger = RuleTrigger(
            ecosystem="maven",
            package="log4j-core",
            version="2.14.0",
            detected_at="2024-01-15T00:00:00Z",
        )

        rule = WafRuleState(
            rule_id="test-rule",
            cve_ids=["CVE-2021-44228"],
            created_at="2024-01-15T00:00:00Z",
            mode="log",
            provider="aws",
            triggered_by=trigger,
            status="active",
        )

        state = WafState(
            version=1,
            generated_at="2024-01-15T00:00:00Z",
            rules=[rule],
        )

        promoted = manager.promote_rule(state, "test-rule")

        assert promoted is not None
        assert promoted.mode == "block"
        assert promoted.promoted_at is not None

    def test_get_status_report(self, manager: WafLifecycleManager) -> None:
        """Test generating status report."""
        trigger = RuleTrigger(
            ecosystem="maven",
            package="log4j-core",
            version="2.14.0",
            detected_at="2024-01-15T00:00:00Z",
        )

        rules = [
            WafRuleState(
                rule_id="log-rule",
                cve_ids=["CVE-2021-44228"],
                created_at="2024-01-15T00:00:00Z",
                mode="log",
                provider="aws",
                triggered_by=trigger,
                status="active",
            ),
            WafRuleState(
                rule_id="block-rule",
                cve_ids=["CVE-2022-22965"],
                created_at="2024-01-15T00:00:00Z",
                mode="block",
                provider="aws",
                triggered_by=trigger,
                status="active",
            ),
        ]

        state = WafState(
            version=1,
            generated_at="2024-01-15T00:00:00Z",
            rules=rules,
        )

        report = manager.get_status_report(state)

        assert report["total_rules"] == 2
        assert report["active_rules"] == 2
        assert report["log_mode_rules"] == 1
        assert report["block_mode_rules"] == 1


class TestLifecycleAnalysis:
    """Tests for LifecycleAnalysis."""

    def test_empty_analysis(self) -> None:
        """Test empty analysis."""
        analysis = LifecycleAnalysis(
            new_rules=[],
            obsolete_rules=[],
            promotion_candidates=[],
            unchanged_rules=[],
            summary="No changes",
        )

        assert len(analysis.new_rules) == 0
        assert len(analysis.obsolete_rules) == 0


class TestMrCreator:
    """Tests for MrCreator."""

    @pytest.fixture
    def creator(self) -> MrCreator:
        """Create MR creator instance."""
        return MrCreator()

    def test_generate_branch_name(self, creator: MrCreator) -> None:
        """Test branch name generation."""
        branch = creator.generate_branch_name()

        assert branch.startswith("blastauri/waf-")
        assert len(branch) > 20  # Has timestamp

    def test_generate_waf_update_title(self, creator: MrCreator) -> None:
        """Test WAF update title generation."""
        # No changes
        title = creator.generate_waf_update_title()
        assert "update WAF configuration" in title

        # New rules
        title = creator.generate_waf_update_title(new_rules=3)
        assert "add 3 rule(s)" in title

        # Removed rules
        title = creator.generate_waf_update_title(removed_rules=2)
        assert "remove 2 rule(s)" in title

        # Promoted rules
        title = creator.generate_waf_update_title(promoted_rules=1)
        assert "promote 1 rule(s)" in title

        # Combined
        title = creator.generate_waf_update_title(
            new_rules=2, removed_rules=1, promoted_rules=3
        )
        assert "add 2 rule(s)" in title
        assert "remove 1 rule(s)" in title
        assert "promote 3 rule(s)" in title

    def test_generate_waf_update_description(self, creator: MrCreator) -> None:
        """Test WAF update description generation."""
        new_rules = [
            {
                "rule_id": "blastauri-log4j",
                "cve_ids": ["CVE-2021-44228"],
                "package": "log4j-core",
                "reason": "New vulnerability",
            }
        ]

        removed_rules = [
            {
                "rule_id": "old-rule",
                "cve_ids": ["CVE-2020-1234"],
                "reason": "Patched",
            }
        ]

        promoted_rules = [
            {
                "rule_id": "promoted-rule",
                "cve_ids": ["CVE-2022-22965"],
                "days_active": "15",
            }
        ]

        terraform_files = ["main.tf", "variables.tf"]

        description = creator.generate_waf_update_description(
            new_rules=new_rules,
            removed_rules=removed_rules,
            promoted_rules=promoted_rules,
            terraform_files=terraform_files,
        )

        assert "WAF Rule Update" in description
        assert "New Rules" in description
        assert "Removed Rules" in description
        assert "Promoted Rules" in description
        assert "blastauri-log4j" in description
        assert "CVE-2021-44228" in description
        assert "main.tf" in description


class TestFileChange:
    """Tests for FileChange dataclass."""

    def test_create_file_change(self) -> None:
        """Test creating file change."""
        change = FileChange(
            path="terraform/waf/main.tf",
            content="resource {}",
            commit_message="Update WAF",
        )

        assert change.path == "terraform/waf/main.tf"
        assert change.content == "resource {}"
        assert change.commit_message == "Update WAF"


class TestMrCreationConfig:
    """Tests for MrCreationConfig."""

    def test_default_config(self) -> None:
        """Test default configuration."""
        config = MrCreationConfig()

        assert config.target_branch == "main"
        assert config.branch_prefix == "blastauri/waf"
        assert config.auto_merge is False
        assert "blastauri" in config.labels

    def test_custom_config(self) -> None:
        """Test custom configuration."""
        config = MrCreationConfig(
            target_branch="develop",
            branch_prefix="security/waf",
            auto_merge=True,
            labels=["security", "automated"],
        )

        assert config.target_branch == "develop"
        assert config.branch_prefix == "security/waf"
        assert config.auto_merge is True


class TestWafSyncConfig:
    """Tests for WafSyncConfig."""

    def test_default_config(self) -> None:
        """Test default configuration."""
        config = WafSyncConfig()

        assert config.provider == WafProviderType.AWS
        assert config.mode == WafRuleMode.LOG
        assert config.output_dir == "./terraform/waf"
        assert config.promotion_days == 14

    def test_custom_config(self) -> None:
        """Test custom configuration."""
        config = WafSyncConfig(
            provider=WafProviderType.CLOUDFLARE,
            mode=WafRuleMode.BLOCK,
            output_dir="/custom/path",
            promotion_days=7,
        )

        assert config.provider == WafProviderType.CLOUDFLARE
        assert config.mode == WafRuleMode.BLOCK
        assert config.output_dir == "/custom/path"
        assert config.promotion_days == 7


class TestWafSyncOrchestrator:
    """Tests for WafSyncOrchestrator."""

    @pytest.fixture
    def temp_repo(self) -> Path:
        """Create temporary repository directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def orchestrator(self, temp_repo: Path) -> WafSyncOrchestrator:
        """Create orchestrator instance."""
        config = WafSyncConfig(
            provider=WafProviderType.AWS,
            create_mr=False,
        )
        return WafSyncOrchestrator(str(temp_repo), config)

    def test_get_status_empty(self, orchestrator: WafSyncOrchestrator) -> None:
        """Test getting status with no state."""
        status = orchestrator.get_status()

        assert status["total_rules"] == 0
        assert status["provider"] == "aws"


class TestWafMrCreator:
    """Tests for WafMrCreator."""

    @pytest.fixture
    def temp_repo(self) -> Path:
        """Create temporary repository directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create terraform directory with files
            tf_dir = Path(tmpdir) / "terraform" / "waf"
            tf_dir.mkdir(parents=True)
            (tf_dir / "main.tf").write_text("resource {}")

            # Create state file
            state_dir = Path(tmpdir) / ".blastauri"
            state_dir.mkdir()
            (state_dir / "waf-state.json").write_text('{"version": 1}')

            yield Path(tmpdir)

    @pytest.fixture
    def creator(self, temp_repo: Path) -> WafMrCreator:
        """Create WAF MR creator instance."""
        return WafMrCreator(str(temp_repo))

    def test_collect_terraform_files(
        self, creator: WafMrCreator, temp_repo: Path
    ) -> None:
        """Test collecting Terraform files."""
        tf_dir = temp_repo / "terraform" / "waf"
        state_file = temp_repo / ".blastauri" / "waf-state.json"

        files = creator.collect_terraform_files(tf_dir, state_file)

        assert len(files) == 2  # main.tf + waf-state.json

        paths = [f.path for f in files]
        assert any("main.tf" in p for p in paths)
        assert any("waf-state.json" in p for p in paths)

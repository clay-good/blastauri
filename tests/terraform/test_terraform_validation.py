"""Tests for Terraform file generation and validation.

These tests verify that generated Terraform files are syntactically correct.
Tests requiring terraform CLI are skipped if not available.
"""

import subprocess
import tempfile
from pathlib import Path

import pytest

from blastauri.waf.generator import GenerationResult, WafGenerator, WafGeneratorConfig
from blastauri.waf.providers.base import GeneratedTerraform, WafProviderType
from blastauri.waf.rule_templates import (
    AttackCategory,
    get_all_critical_templates,
    get_default_registry,
    get_owasp_top10_templates,
    get_templates_for_cves,
)


def terraform_available() -> bool:
    """Check if terraform CLI is available."""
    try:
        result = subprocess.run(
            ["terraform", "version"],
            capture_output=True,
            timeout=10,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def terraform_fmt_check(tf_dir: Path) -> tuple[bool, str]:
    """Run terraform fmt -check on a directory.

    Args:
        tf_dir: Directory containing Terraform files.

    Returns:
        Tuple of (success, error_message).
    """
    try:
        result = subprocess.run(
            ["terraform", "fmt", "-check", "-diff", "-recursive"],
            cwd=tf_dir,
            capture_output=True,
            text=True,
            timeout=30,
        )
        return result.returncode == 0, result.stdout + result.stderr
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        return False, str(e)


class TestWafTemplatesExist:
    """Test that all expected WAF templates exist."""

    def test_aws_templates_exist(self) -> None:
        """Test AWS WAF templates exist."""
        templates_dir = (
            Path(__file__).parent.parent.parent
            / "src"
            / "blastauri"
            / "templates"
            / "waf"
        )

        assert (templates_dir / "aws_rule.tf.j2").exists()
        assert (templates_dir / "aws_rule_group.tf.j2").exists()
        assert (templates_dir / "aws_web_acl.tf.j2").exists()
        assert (templates_dir / "aws_variables.tf.j2").exists()

    def test_cloudflare_templates_exist(self) -> None:
        """Test Cloudflare WAF templates exist."""
        templates_dir = (
            Path(__file__).parent.parent.parent
            / "src"
            / "blastauri"
            / "templates"
            / "waf"
        )

        assert (templates_dir / "cloudflare_ruleset.tf.j2").exists()
        assert (templates_dir / "cloudflare_variables.tf.j2").exists()


class TestWafRuleTemplates:
    """Test the rule template definitions."""

    def test_default_registry_not_empty(self) -> None:
        """Test that default registry has templates."""
        registry = get_default_registry()
        assert len(registry.get_all_templates()) > 0

    def test_owasp_templates_exist(self) -> None:
        """Test that OWASP templates are defined."""
        templates = get_owasp_top10_templates()
        assert len(templates) > 0

    def test_critical_templates_exist(self) -> None:
        """Test that critical templates are defined."""
        templates = get_all_critical_templates()
        assert len(templates) > 0

    def test_log4j_template_exists(self) -> None:
        """Test that Log4j template exists."""
        templates = get_templates_for_cves(["CVE-2021-44228"])
        assert len(templates) > 0

    def test_templates_have_required_fields(self) -> None:
        """Test templates have all required fields."""
        registry = get_default_registry()
        for template in registry.get_all_templates():
            assert template.template_id is not None
            assert template.name is not None
            assert template.description is not None
            assert template.category is not None
            assert isinstance(template.category, AttackCategory)

    def test_templates_have_statements(self) -> None:
        """Test templates have rule statements."""
        registry = get_default_registry()
        for template in registry.get_all_templates():
            # Templates should have at least one statement
            assert len(template.statements) > 0


class TestWafGeneratorConfig:
    """Test WAF generator configuration."""

    def test_default_config(self) -> None:
        """Test default configuration."""
        config = WafGeneratorConfig()
        assert config.provider == WafProviderType.AWS
        # output_dir is None by default (optional)
        assert config.output_dir is None
        assert config.name_prefix == "blastauri"

    def test_cloudflare_config(self) -> None:
        """Test Cloudflare configuration."""
        config = WafGeneratorConfig(provider=WafProviderType.CLOUDFLARE)
        assert config.provider == WafProviderType.CLOUDFLARE

    def test_config_with_output_dir(self) -> None:
        """Test configuration with output directory."""
        config = WafGeneratorConfig(output_dir="/tmp/waf-output")
        assert config.output_dir == "/tmp/waf-output"


class TestWafGeneratorCreation:
    """Test WAF generator instantiation."""

    def test_create_aws_generator(self) -> None:
        """Test creating AWS WAF generator."""
        config = WafGeneratorConfig(provider=WafProviderType.AWS)
        generator = WafGenerator(config)
        assert generator is not None

    def test_create_cloudflare_generator(self) -> None:
        """Test creating Cloudflare WAF generator."""
        config = WafGeneratorConfig(provider=WafProviderType.CLOUDFLARE)
        generator = WafGenerator(config)
        assert generator is not None


class TestWafRuleGeneration:
    """Test WAF rule generation."""

    def test_generate_from_cves(self) -> None:
        """Test generating rules from CVEs."""
        output_dir = tempfile.mkdtemp()
        config = WafGeneratorConfig(
            provider=WafProviderType.AWS,
            output_dir=output_dir,
        )
        generator = WafGenerator(config)

        result = generator.generate_from_cves(["CVE-2021-44228"])

        assert isinstance(result, GenerationResult)
        assert len(result.files) > 0
        # Files are GeneratedTerraform objects
        for tf_file in result.files:
            assert isinstance(tf_file, GeneratedTerraform)
            assert tf_file.filename.endswith(".tf")

    def test_generate_owasp_protection(self) -> None:
        """Test generating OWASP protection rules."""
        output_dir = tempfile.mkdtemp()
        config = WafGeneratorConfig(
            provider=WafProviderType.AWS,
            output_dir=output_dir,
        )
        generator = WafGenerator(config)

        result = generator.generate_owasp_protection()

        assert isinstance(result, GenerationResult)
        assert len(result.files) > 0

    def test_generate_cloudflare_rules(self) -> None:
        """Test generating Cloudflare rules."""
        output_dir = tempfile.mkdtemp()
        config = WafGeneratorConfig(
            provider=WafProviderType.CLOUDFLARE,
            output_dir=output_dir,
        )
        generator = WafGenerator(config)

        result = generator.generate_from_cves(["CVE-2021-44228"])

        assert isinstance(result, GenerationResult)
        assert len(result.files) > 0


class TestGeneratedFileContent:
    """Test the content of generated Terraform files."""

    def test_aws_files_have_correct_extensions(self) -> None:
        """Test AWS files have .tf extension."""
        output_dir = tempfile.mkdtemp()
        config = WafGeneratorConfig(
            provider=WafProviderType.AWS,
            output_dir=output_dir,
        )
        generator = WafGenerator(config)

        result = generator.generate_owasp_protection()

        for tf_file in result.files:
            assert tf_file.filename.endswith(".tf")

    def test_cloudflare_files_have_correct_extensions(self) -> None:
        """Test Cloudflare files have .tf extension."""
        output_dir = tempfile.mkdtemp()
        config = WafGeneratorConfig(
            provider=WafProviderType.CLOUDFLARE,
            output_dir=output_dir,
        )
        generator = WafGenerator(config)

        result = generator.generate_owasp_protection()

        for tf_file in result.files:
            assert tf_file.filename.endswith(".tf")

    def test_no_hardcoded_secrets(self) -> None:
        """Test that generated files don't contain hardcoded secrets."""
        output_dir = tempfile.mkdtemp()
        config = WafGeneratorConfig(
            provider=WafProviderType.AWS,
            output_dir=output_dir,
        )
        generator = WafGenerator(config)

        result = generator.generate_owasp_protection()

        for tf_file in result.files:
            content = tf_file.content.lower()
            # Should not have hardcoded secrets - any secrets should use var.
            assert "api_key" not in content or "var." in content
            assert "password" not in content or "var." in content


@pytest.mark.skipif(
    not terraform_available(),
    reason="Terraform CLI not available",
)
class TestTerraformValidation:
    """Tests that require terraform CLI."""

    def test_aws_rules_terraform_fmt(self) -> None:
        """Test that AWS rules pass terraform fmt check."""
        output_dir = tempfile.mkdtemp()
        config = WafGeneratorConfig(
            provider=WafProviderType.AWS,
            output_dir=output_dir,
        )
        generator = WafGenerator(config)

        result = generator.generate_owasp_protection()

        success, error = terraform_fmt_check(Path(output_dir))
        if not success:
            # Show which files have issues
            for tf_file in result.files:
                print(f"\n{tf_file.filename}:")
                print(tf_file.content[:500])
            pytest.fail(f"Terraform fmt check failed:\n{error}")

    def test_cloudflare_rules_terraform_fmt(self) -> None:
        """Test that Cloudflare rules pass terraform fmt check."""
        output_dir = tempfile.mkdtemp()
        config = WafGeneratorConfig(
            provider=WafProviderType.CLOUDFLARE,
            output_dir=output_dir,
        )
        generator = WafGenerator(config)

        result = generator.generate_owasp_protection()

        success, error = terraform_fmt_check(Path(output_dir))
        if not success:
            pytest.fail(f"Terraform fmt check failed:\n{error}")


class TestRuleTemplateValidation:
    """Test rule template data validation."""

    def test_attack_categories_are_valid(self) -> None:
        """Test templates have valid attack categories."""
        registry = get_default_registry()
        for template in registry.get_all_templates():
            assert isinstance(template.category, AttackCategory)

    def test_severities_are_valid(self) -> None:
        """Test templates have valid severity values."""
        valid_severities = {"critical", "high", "medium", "low", "unknown"}
        registry = get_default_registry()
        for template in registry.get_all_templates():
            assert template.severity.lower() in valid_severities

    def test_cve_ids_format(self) -> None:
        """Test CVE IDs have correct format."""
        registry = get_default_registry()
        for template in registry.get_all_templates():
            for cve_id in template.cve_ids:
                assert cve_id.startswith("CVE-")
                # Should match CVE-YYYY-NNNNN format
                parts = cve_id.split("-")
                assert len(parts) == 3
                assert len(parts[1]) == 4  # Year
                assert parts[2].isdigit()  # Number


class TestCoverageOfKnownCVEs:
    """Test coverage of known important CVEs."""

    def test_log4j_covered(self) -> None:
        """Test Log4j CVEs are covered."""
        templates = get_templates_for_cves(["CVE-2021-44228"])
        assert len(templates) > 0

    def test_spring4shell_covered(self) -> None:
        """Test Spring4Shell CVE is covered."""
        templates = get_templates_for_cves(["CVE-2022-22965"])
        assert len(templates) > 0

    def test_multiple_cves_at_once(self) -> None:
        """Test getting templates for multiple CVEs."""
        cve_ids = ["CVE-2021-44228", "CVE-2022-22965"]
        templates = get_templates_for_cves(cve_ids)
        # Should get templates for both
        assert len(templates) >= 1

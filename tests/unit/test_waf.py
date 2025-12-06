"""Tests for WAF rule generation module."""

import tempfile
from pathlib import Path

import pytest

from blastauri.waf.generator import (
    GenerationResult,
    WafGenerator,
    WafGeneratorConfig,
    generate_owasp_rules,
    generate_waf_rules,
)
from blastauri.waf.providers.aws import AwsWafProvider
from blastauri.waf.providers.base import (
    GeneratedTerraform,
    WafProviderType,
    WafRuleConfig,
    WafRuleDefinition,
    WafRuleMode,
    WafRuleStatement,
    WafScope,
)
from blastauri.waf.providers.cloudflare import CloudflareWafProvider
from blastauri.waf.rule_templates import (
    AttackCategory,
    RuleTemplate,
    RuleTemplateRegistry,
    get_all_critical_templates,
    get_default_registry,
    get_owasp_top10_templates,
    get_templates_for_cves,
)


class TestWafRuleConfig:
    """Tests for WafRuleConfig dataclass."""

    def test_default_tags(self) -> None:
        """Test default tags are applied."""
        config = WafRuleConfig(
            rule_id="test-rule",
            name="Test Rule",
            description="Test description",
            priority=1,
        )

        assert "ManagedBy" in config.tags
        assert config.tags["ManagedBy"] == "blastauri"

    def test_custom_tags_preserved(self) -> None:
        """Test custom tags are preserved."""
        config = WafRuleConfig(
            rule_id="test-rule",
            name="Test Rule",
            description="Test description",
            priority=1,
            tags={"Custom": "value"},
        )

        assert "Custom" in config.tags
        assert config.tags["Custom"] == "value"
        assert "ManagedBy" in config.tags

    def test_cve_ids(self) -> None:
        """Test CVE IDs are stored."""
        config = WafRuleConfig(
            rule_id="test-rule",
            name="Test Rule",
            description="Test description",
            priority=1,
            cve_ids=["CVE-2021-44228", "CVE-2021-45046"],
        )

        assert len(config.cve_ids) == 2
        assert "CVE-2021-44228" in config.cve_ids


class TestWafRuleStatement:
    """Tests for WafRuleStatement dataclass."""

    def test_default_values(self) -> None:
        """Test default values."""
        stmt = WafRuleStatement(field_type="uri")

        assert stmt.match_type == "contains"
        assert stmt.patterns == []
        assert stmt.transformations == []
        assert stmt.negate is False

    def test_with_patterns(self) -> None:
        """Test with patterns."""
        stmt = WafRuleStatement(
            field_type="uri",
            match_type="regex",
            patterns=[r"\$\{jndi:"],
            transformations=["lowercase", "url_decode"],
        )

        assert stmt.match_type == "regex"
        assert len(stmt.patterns) == 1
        assert "lowercase" in stmt.transformations


class TestWafRuleDefinition:
    """Tests for WafRuleDefinition dataclass."""

    def test_default_logic(self) -> None:
        """Test default logic is 'or'."""
        config = WafRuleConfig(
            rule_id="test",
            name="Test",
            description="Test",
            priority=1,
        )
        rule_def = WafRuleDefinition(config=config)

        assert rule_def.logic == "or"
        assert rule_def.statements == []


class TestAwsWafProvider:
    """Tests for AWS WAF provider."""

    @pytest.fixture
    def provider(self) -> AwsWafProvider:
        """Create AWS provider instance."""
        return AwsWafProvider(
            mode=WafRuleMode.LOG,
            scope=WafScope.REGIONAL,
            name_prefix="test",
        )

    def test_provider_type(self, provider: AwsWafProvider) -> None:
        """Test provider type is AWS."""
        assert provider.provider_type == WafProviderType.AWS

    def test_sanitize_name(self, provider: AwsWafProvider) -> None:
        """Test name sanitization."""
        assert provider._sanitize_name("Test Rule") == "test-rule"
        assert provider._sanitize_name("test.rule") == "test-rule"
        assert provider._sanitize_name("test_rule") == "test-rule"
        assert provider._sanitize_name("Test--Rule") == "test-rule"

    def test_escape_hcl_string(self, provider: AwsWafProvider) -> None:
        """Test HCL string escaping."""
        assert provider._escape_hcl_string('test"quote') == 'test\\"quote'
        assert provider._escape_hcl_string("test\\slash") == "test\\\\slash"

    def test_generate_rule_block_mode(self, provider: AwsWafProvider) -> None:
        """Test rule generation with block mode."""
        config = WafRuleConfig(
            rule_id="test",
            name="Test Rule",
            description="Test",
            priority=1,
            mode=WafRuleMode.BLOCK,
        )
        stmt = WafRuleStatement(
            field_type="uri",
            match_type="contains",
            patterns=["test"],
        )
        rule_def = WafRuleDefinition(config=config, statements=[stmt])

        hcl = provider.generate_rule(rule_def)

        assert "block {}" in hcl
        assert 'name     = "Test Rule"' in hcl
        assert "priority = 1" in hcl

    def test_generate_rule_count_mode(self, provider: AwsWafProvider) -> None:
        """Test rule generation with count mode."""
        config = WafRuleConfig(
            rule_id="test",
            name="Test Rule",
            description="Test",
            priority=1,
            mode=WafRuleMode.LOG,
        )
        stmt = WafRuleStatement(
            field_type="uri",
            match_type="contains",
            patterns=["test"],
        )
        rule_def = WafRuleDefinition(config=config, statements=[stmt])

        hcl = provider.generate_rule(rule_def)

        assert "count {}" in hcl

    def test_generate_field_to_match_uri(self, provider: AwsWafProvider) -> None:
        """Test field_to_match for URI."""
        stmt = WafRuleStatement(field_type="uri", patterns=["test"])
        field_hcl = provider._generate_field_to_match(stmt)

        assert "uri_path {}" in field_hcl

    def test_generate_field_to_match_header(self, provider: AwsWafProvider) -> None:
        """Test field_to_match for header."""
        stmt = WafRuleStatement(
            field_type="header",
            field_name="User-Agent",
            patterns=["test"],
        )
        field_hcl = provider._generate_field_to_match(stmt)

        assert "single_header" in field_hcl
        assert 'name = "user-agent"' in field_hcl

    def test_generate_field_to_match_body(self, provider: AwsWafProvider) -> None:
        """Test field_to_match for body."""
        stmt = WafRuleStatement(field_type="body", patterns=["test"])
        field_hcl = provider._generate_field_to_match(stmt)

        assert "body {" in field_hcl
        assert 'oversize_handling = "CONTINUE"' in field_hcl

    def test_generate_text_transformations(self, provider: AwsWafProvider) -> None:
        """Test text transformation generation."""
        transforms = provider._generate_text_transformations(
            ["lowercase", "url_decode"]
        )

        assert 'type     = "LOWERCASE"' in transforms
        assert 'type     = "URL_DECODE"' in transforms
        assert "priority = 0" in transforms
        assert "priority = 1" in transforms

    def test_generate_text_transformations_none(self, provider: AwsWafProvider) -> None:
        """Test text transformation with empty list."""
        transforms = provider._generate_text_transformations([])

        assert 'type     = "NONE"' in transforms

    def test_generate_rule_group(self, provider: AwsWafProvider) -> None:
        """Test rule group generation."""
        config = WafRuleConfig(
            rule_id="test",
            name="Test Rule",
            description="Test",
            priority=1,
        )
        stmt = WafRuleStatement(
            field_type="uri",
            match_type="contains",
            patterns=["test"],
        )
        rule_def = WafRuleDefinition(config=config, statements=[stmt])

        hcl = provider.generate_rule_group("test-group", [rule_def], "Test group")

        assert 'resource "aws_wafv2_rule_group"' in hcl
        assert 'name        = "test-group"' in hcl
        assert "capacity    =" in hcl
        assert "visibility_config" in hcl

    def test_generate_web_acl(self, provider: AwsWafProvider) -> None:
        """Test web ACL generation."""
        hcl = provider.generate_web_acl(
            "test-acl",
            ["aws_wafv2_rule_group.test.arn"],
            "Test ACL",
        )

        assert 'resource "aws_wafv2_web_acl"' in hcl
        assert 'name        = "test-acl"' in hcl
        assert "default_action" in hcl
        assert "allow {}" in hcl

    def test_generate_complete_config(self, provider: AwsWafProvider) -> None:
        """Test complete configuration generation."""
        config = WafRuleConfig(
            rule_id="test",
            name="Test Rule",
            description="Test",
            priority=1,
        )
        stmt = WafRuleStatement(
            field_type="uri",
            match_type="contains",
            patterns=["test"],
        )
        rule_def = WafRuleDefinition(config=config, statements=[stmt])

        files = provider.generate_complete_config([rule_def], "test-waf")

        assert len(files) == 3
        filenames = [f.filename for f in files]
        assert "main.tf" in filenames
        assert "variables.tf" in filenames
        assert "outputs.tf" in filenames

        for f in files:
            assert f.provider == WafProviderType.AWS


class TestCloudflareWafProvider:
    """Tests for Cloudflare WAF provider."""

    @pytest.fixture
    def provider(self) -> CloudflareWafProvider:
        """Create Cloudflare provider instance."""
        return CloudflareWafProvider(
            mode=WafRuleMode.LOG,
            name_prefix="test",
        )

    def test_provider_type(self, provider: CloudflareWafProvider) -> None:
        """Test provider type is Cloudflare."""
        assert provider.provider_type == WafProviderType.CLOUDFLARE

    def test_generate_expression_single(self, provider: CloudflareWafProvider) -> None:
        """Test single expression generation."""
        stmt = WafRuleStatement(
            field_type="uri",
            match_type="contains",
            patterns=["test"],
        )

        expr = provider._generate_expression([stmt], "or")

        assert 'http.request.uri.path contains "test"' in expr

    def test_generate_expression_multiple_or(
        self, provider: CloudflareWafProvider
    ) -> None:
        """Test multiple expressions with OR logic."""
        stmts = [
            WafRuleStatement(
                field_type="uri",
                match_type="contains",
                patterns=["test1"],
            ),
            WafRuleStatement(
                field_type="uri",
                match_type="contains",
                patterns=["test2"],
            ),
        ]

        expr = provider._generate_expression(stmts, "or")

        assert " or " in expr

    def test_generate_expression_multiple_and(
        self, provider: CloudflareWafProvider
    ) -> None:
        """Test multiple expressions with AND logic."""
        stmts = [
            WafRuleStatement(
                field_type="uri",
                match_type="contains",
                patterns=["test1"],
            ),
            WafRuleStatement(
                field_type="uri",
                match_type="contains",
                patterns=["test2"],
            ),
        ]

        expr = provider._generate_expression(stmts, "and")

        assert " and " in expr

    def test_apply_transformations(self, provider: CloudflareWafProvider) -> None:
        """Test transformation application."""
        result = provider._apply_transformations(
            "http.request.uri.path",
            ["lowercase", "url_decode"],
        )

        assert "lower(" in result
        assert "url_decode(" in result

    def test_generate_regex_expression(self, provider: CloudflareWafProvider) -> None:
        """Test regex expression generation."""
        expr = provider._generate_regex_expression(
            "http.request.uri.path",
            [r"\$\{jndi:"],
            False,
        )

        assert "~" in expr
        assert "${jndi:" in expr

    def test_generate_exact_expression_single(
        self, provider: CloudflareWafProvider
    ) -> None:
        """Test exact match with single pattern."""
        expr = provider._generate_exact_expression(
            "http.request.method",
            ["GET"],
            False,
        )

        assert "eq" in expr
        assert '"GET"' in expr

    def test_generate_exact_expression_multiple(
        self, provider: CloudflareWafProvider
    ) -> None:
        """Test exact match with multiple patterns."""
        expr = provider._generate_exact_expression(
            "http.request.method",
            ["GET", "POST"],
            False,
        )

        assert " in " in expr

    def test_generate_contains_expression(
        self, provider: CloudflareWafProvider
    ) -> None:
        """Test contains expression generation."""
        expr = provider._generate_contains_expression(
            "http.request.uri.path",
            ["test"],
            False,
        )

        assert "contains" in expr

    def test_generate_rule_group(self, provider: CloudflareWafProvider) -> None:
        """Test ruleset generation."""
        config = WafRuleConfig(
            rule_id="test",
            name="Test Rule",
            description="Test",
            priority=1,
        )
        stmt = WafRuleStatement(
            field_type="uri",
            match_type="contains",
            patterns=["test"],
        )
        rule_def = WafRuleDefinition(config=config, statements=[stmt])

        hcl = provider.generate_rule_group("test-group", [rule_def], "Test group")

        assert 'resource "cloudflare_ruleset"' in hcl
        assert "zone_id" in hcl
        assert 'phase       = "http_request_firewall_custom"' in hcl

    def test_generate_rate_limit_rule(self, provider: CloudflareWafProvider) -> None:
        """Test rate limit rule generation."""
        hcl = provider.generate_rate_limit_rule(
            name="test-rate-limit",
            requests_per_period=100,
            period=60,
        )

        assert 'resource "cloudflare_ruleset"' in hcl
        assert "http_ratelimit" in hcl
        assert "requests_per_period = 100" in hcl

    def test_generate_complete_config(self, provider: CloudflareWafProvider) -> None:
        """Test complete configuration generation."""
        config = WafRuleConfig(
            rule_id="test",
            name="Test Rule",
            description="Test",
            priority=1,
        )
        stmt = WafRuleStatement(
            field_type="uri",
            match_type="contains",
            patterns=["test"],
        )
        rule_def = WafRuleDefinition(config=config, statements=[stmt])

        files = provider.generate_complete_config([rule_def], "test-waf")

        assert len(files) == 3
        for f in files:
            assert f.provider == WafProviderType.CLOUDFLARE


class TestRuleTemplateRegistry:
    """Tests for RuleTemplateRegistry."""

    @pytest.fixture
    def registry(self) -> RuleTemplateRegistry:
        """Create registry instance."""
        return RuleTemplateRegistry()

    def test_builtin_templates_loaded(self, registry: RuleTemplateRegistry) -> None:
        """Test built-in templates are loaded."""
        templates = registry.get_all_templates()
        assert len(templates) > 0

    def test_get_template_log4shell(self, registry: RuleTemplateRegistry) -> None:
        """Test getting Log4Shell template."""
        template = registry.get_template("log4shell-jndi")
        assert template is not None
        assert "CVE-2021-44228" in template.cve_ids

    def test_get_templates_for_cve(self, registry: RuleTemplateRegistry) -> None:
        """Test getting templates for a CVE."""
        templates = registry.get_templates_for_cve("CVE-2021-44228")
        assert len(templates) > 0

    def test_has_template_for_cve(self, registry: RuleTemplateRegistry) -> None:
        """Test checking CVE coverage."""
        assert registry.has_template_for_cve("CVE-2021-44228")
        assert not registry.has_template_for_cve("CVE-9999-99999")

    def test_get_templates_for_category(self, registry: RuleTemplateRegistry) -> None:
        """Test getting templates by category."""
        templates = registry.get_templates_for_category(AttackCategory.SQL_INJECTION)
        assert len(templates) > 0
        for t in templates:
            assert t.category == AttackCategory.SQL_INJECTION

    def test_register_custom_template(self, registry: RuleTemplateRegistry) -> None:
        """Test registering custom template."""
        custom = RuleTemplate(
            template_id="custom-test",
            name="Custom Test",
            description="Custom test template",
            category=AttackCategory.GENERIC,
            statements=[
                WafRuleStatement(
                    field_type="uri",
                    match_type="contains",
                    patterns=["custom"],
                )
            ],
        )

        registry.register(custom)

        retrieved = registry.get_template("custom-test")
        assert retrieved is not None
        assert retrieved.name == "Custom Test"


class TestRuleTemplate:
    """Tests for RuleTemplate."""

    def test_to_rule_definition(self) -> None:
        """Test converting template to rule definition."""
        template = RuleTemplate(
            template_id="test",
            name="Test Template",
            description="Test description",
            category=AttackCategory.GENERIC,
            cve_ids=["CVE-2021-44228"],
            statements=[
                WafRuleStatement(
                    field_type="uri",
                    match_type="contains",
                    patterns=["test"],
                )
            ],
            severity="critical",
        )

        rule_def = template.to_rule_definition(priority=5, mode=WafRuleMode.BLOCK)

        assert rule_def.config.priority == 5
        assert rule_def.config.mode == WafRuleMode.BLOCK
        assert rule_def.config.name == "Test Template"
        assert "CVE-2021-44228" in rule_def.config.cve_ids
        assert rule_def.config.tags["Severity"] == "critical"


class TestWafGenerator:
    """Tests for WafGenerator."""

    @pytest.fixture
    def generator(self) -> WafGenerator:
        """Create generator instance."""
        config = WafGeneratorConfig(
            provider=WafProviderType.AWS,
            mode=WafRuleMode.LOG,
        )
        return WafGenerator(config)

    def test_generate_from_cves(self, generator: WafGenerator) -> None:
        """Test generating rules from CVEs."""
        result = generator.generate_from_cves(["CVE-2021-44228"])

        assert result.rules_count > 0
        assert "CVE-2021-44228" in result.cves_covered
        assert len(result.files) == 3

    def test_generate_from_unknown_cve(self, generator: WafGenerator) -> None:
        """Test generating rules from unknown CVE."""
        result = generator.generate_from_cves(["CVE-9999-99999"])

        assert result.rules_count == 0
        assert len(result.warnings) > 0
        assert any("CVE-9999-99999" in w for w in result.warnings)

    def test_generate_from_templates(self, generator: WafGenerator) -> None:
        """Test generating rules from template IDs."""
        result = generator.generate_from_templates(["log4shell-jndi", "spring4shell"])

        assert result.rules_count == 2
        assert "log4shell-jndi" in result.templates_used
        assert "spring4shell" in result.templates_used

    def test_generate_owasp_protection(self, generator: WafGenerator) -> None:
        """Test generating OWASP protection rules."""
        result = generator.generate_owasp_protection()

        assert result.rules_count > 0
        assert len(result.files) == 3

    def test_generate_critical_protection(self, generator: WafGenerator) -> None:
        """Test generating critical CVE protection rules."""
        result = generator.generate_critical_protection()

        assert result.rules_count > 0
        assert len(result.cves_covered) > 0

    def test_generate_with_output_dir(self) -> None:
        """Test generating with output directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = WafGeneratorConfig(
                provider=WafProviderType.AWS,
                output_dir=tmpdir,
            )
            generator = WafGenerator(config)

            result = generator.generate_from_cves(["CVE-2021-44228"])

            assert result.rules_count > 0

            output_path = Path(tmpdir)
            assert (output_path / "main.tf").exists()
            assert (output_path / "variables.tf").exists()
            assert (output_path / "outputs.tf").exists()

    def test_list_available_templates(self, generator: WafGenerator) -> None:
        """Test listing available templates."""
        templates = generator.list_available_templates()

        assert len(templates) > 0
        for t in templates:
            assert "id" in t
            assert "name" in t
            assert "category" in t

    def test_list_cve_coverage(self, generator: WafGenerator) -> None:
        """Test listing CVE coverage."""
        coverage = generator.list_cve_coverage()

        assert len(coverage) > 0
        assert "CVE-2021-44228" in coverage


class TestConvenienceFunctions:
    """Tests for convenience functions."""

    def test_generate_waf_rules(self) -> None:
        """Test generate_waf_rules function."""
        result = generate_waf_rules(["CVE-2021-44228"])

        assert result.rules_count > 0
        assert result.provider == WafProviderType.AWS

    def test_generate_waf_rules_cloudflare(self) -> None:
        """Test generate_waf_rules with Cloudflare."""
        result = generate_waf_rules(
            ["CVE-2021-44228"],
            provider=WafProviderType.CLOUDFLARE,
        )

        assert result.rules_count > 0
        assert result.provider == WafProviderType.CLOUDFLARE

    def test_generate_owasp_rules(self) -> None:
        """Test generate_owasp_rules function."""
        result = generate_owasp_rules()

        assert result.rules_count > 0

    def test_get_templates_for_cves_function(self) -> None:
        """Test get_templates_for_cves function."""
        templates = get_templates_for_cves(["CVE-2021-44228", "CVE-2022-22965"])

        assert len(templates) >= 2

    def test_get_all_critical_templates_function(self) -> None:
        """Test get_all_critical_templates function."""
        templates = get_all_critical_templates()

        assert len(templates) > 0
        for t in templates:
            assert t.severity == "critical"

    def test_get_owasp_top10_templates_function(self) -> None:
        """Test get_owasp_top10_templates function."""
        templates = get_owasp_top10_templates()

        assert len(templates) > 0

    def test_get_default_registry_singleton(self) -> None:
        """Test that get_default_registry returns singleton."""
        registry1 = get_default_registry()
        registry2 = get_default_registry()

        assert registry1 is registry2


class TestGeneratedTerraform:
    """Tests for GeneratedTerraform dataclass."""

    def test_generated_terraform(self) -> None:
        """Test GeneratedTerraform creation."""
        tf = GeneratedTerraform(
            filename="main.tf",
            content='resource "test" {}',
            provider=WafProviderType.AWS,
        )

        assert tf.filename == "main.tf"
        assert tf.content == 'resource "test" {}'
        assert tf.provider == WafProviderType.AWS


class TestAttackCategories:
    """Tests for AttackCategory enum."""

    def test_all_categories_exist(self) -> None:
        """Test all expected categories exist."""
        expected = [
            "sqli",
            "xss",
            "rce",
            "path_traversal",
            "log4j",
            "spring4shell",
            "cmdi",
            "ssrf",
            "xxe",
            "ldapi",
            "generic",
        ]

        for cat in expected:
            assert hasattr(AttackCategory, cat.upper()) or any(
                c.value == cat for c in AttackCategory
            )


class TestWafScope:
    """Tests for WafScope enum."""

    def test_regional_scope(self) -> None:
        """Test REGIONAL scope."""
        assert WafScope.REGIONAL.value == "REGIONAL"

    def test_cloudfront_scope(self) -> None:
        """Test CLOUDFRONT scope."""
        assert WafScope.CLOUDFRONT.value == "CLOUDFRONT"


class TestWafRuleMode:
    """Tests for WafRuleMode enum."""

    def test_log_mode(self) -> None:
        """Test LOG mode."""
        assert WafRuleMode.LOG.value == "log"

    def test_block_mode(self) -> None:
        """Test BLOCK mode."""
        assert WafRuleMode.BLOCK.value == "block"


class TestIntegration:
    """Integration tests for WAF generation."""

    def test_aws_log4shell_full_generation(self) -> None:
        """Test full AWS Log4Shell rule generation."""
        config = WafGeneratorConfig(
            provider=WafProviderType.AWS,
            mode=WafRuleMode.BLOCK,
            scope=WafScope.REGIONAL,
            name_prefix="security",
        )
        generator = WafGenerator(config)
        result = generator.generate_from_cves(["CVE-2021-44228"])

        assert result.rules_count > 0
        assert "CVE-2021-44228" in result.cves_covered

        main_tf = next(f for f in result.files if f.filename == "main.tf")
        assert "aws_wafv2_rule_group" in main_tf.content
        assert "block {}" in main_tf.content
        assert "jndi" in main_tf.content.lower()

    def test_cloudflare_spring4shell_full_generation(self) -> None:
        """Test full Cloudflare Spring4Shell rule generation."""
        config = WafGeneratorConfig(
            provider=WafProviderType.CLOUDFLARE,
            mode=WafRuleMode.LOG,
            name_prefix="security",
        )
        generator = WafGenerator(config)
        result = generator.generate_from_cves(["CVE-2022-22965"])

        assert result.rules_count > 0
        assert "CVE-2022-22965" in result.cves_covered

        main_tf = next(f for f in result.files if f.filename == "main.tf")
        assert "cloudflare_ruleset" in main_tf.content
        assert 'action      = "log"' in main_tf.content

    def test_multiple_cves_combined(self) -> None:
        """Test combining multiple CVE protections."""
        cves = [
            "CVE-2021-44228",  # Log4Shell
            "CVE-2022-22965",  # Spring4Shell
            "CVE-2017-5638",   # Struts
        ]

        result = generate_waf_rules(cves)

        assert result.rules_count >= 3
        for cve in cves:
            assert cve in result.cves_covered

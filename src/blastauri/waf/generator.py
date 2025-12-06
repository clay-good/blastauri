"""Main WAF rule generator.

This module orchestrates WAF rule generation from CVE analysis results,
combining rule templates with provider-specific Terraform generation.
"""

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from blastauri.core.models import CVE, CVEAnalysisResult
from blastauri.waf.providers.aws import AwsWafProvider
from blastauri.waf.providers.base import (
    BaseWafProvider,
    GeneratedTerraform,
    WafProviderType,
    WafRuleDefinition,
    WafRuleMode,
    WafScope,
)
from blastauri.waf.providers.cloudflare import CloudflareWafProvider
from blastauri.waf.rule_templates import (
    AttackCategory,
    RuleTemplate,
    RuleTemplateRegistry,
    get_default_registry,
    get_templates_for_cves,
)


@dataclass
class WafGeneratorConfig:
    """Configuration for WAF rule generation."""

    provider: WafProviderType = WafProviderType.AWS
    mode: WafRuleMode = WafRuleMode.LOG
    scope: WafScope = WafScope.REGIONAL
    name_prefix: str = "blastauri"
    include_owasp: bool = False
    include_critical_only: bool = False
    output_dir: Optional[str] = None
    custom_templates: list[RuleTemplate] = field(default_factory=list)
    tags: dict[str, str] = field(default_factory=dict)


@dataclass
class GenerationResult:
    """Result of WAF rule generation."""

    files: list[GeneratedTerraform]
    rules_count: int
    cves_covered: list[str]
    templates_used: list[str]
    provider: WafProviderType
    warnings: list[str] = field(default_factory=list)


class WafGenerator:
    """Main WAF rule generator.

    Generates Terraform configurations for WAF rules based on
    CVE analysis results and rule templates.
    """

    def __init__(
        self,
        config: Optional[WafGeneratorConfig] = None,
        registry: Optional[RuleTemplateRegistry] = None,
    ) -> None:
        """Initialize the WAF generator.

        Args:
            config: Generator configuration.
            registry: Rule template registry.
        """
        self._config = config or WafGeneratorConfig()
        self._registry = registry or get_default_registry()
        self._provider = self._create_provider()

    def _create_provider(self) -> BaseWafProvider:
        """Create the appropriate WAF provider.

        Returns:
            WAF provider instance.
        """
        if self._config.provider == WafProviderType.AWS:
            return AwsWafProvider(
                mode=self._config.mode,
                scope=self._config.scope,
                name_prefix=self._config.name_prefix,
            )
        elif self._config.provider == WafProviderType.CLOUDFLARE:
            return CloudflareWafProvider(
                mode=self._config.mode,
                scope=self._config.scope,
                name_prefix=self._config.name_prefix,
            )
        else:
            raise ValueError(f"Unsupported provider: {self._config.provider}")

    def generate_from_cves(
        self,
        cve_ids: list[str],
        name: str = "cve-protection",
    ) -> GenerationResult:
        """Generate WAF rules for a list of CVEs.

        Args:
            cve_ids: List of CVE identifiers.
            name: Base name for generated resources.

        Returns:
            GenerationResult with generated files.
        """
        # Get templates for CVEs
        templates = get_templates_for_cves(cve_ids)

        # Add custom templates
        templates.extend(self._config.custom_templates)

        # Filter by severity if requested
        if self._config.include_critical_only:
            templates = [t for t in templates if t.severity == "critical"]

        warnings: list[str] = []

        # Check for CVEs without templates
        covered_cves = set()
        for template in templates:
            covered_cves.update(template.cve_ids)

        missing_cves = set(cve_ids) - covered_cves
        for cve_id in missing_cves:
            warnings.append(f"No WAF rule template available for {cve_id}")

        # Generate rules from templates
        rules = self._templates_to_rules(templates)

        if not rules:
            return GenerationResult(
                files=[],
                rules_count=0,
                cves_covered=[],
                templates_used=[],
                provider=self._config.provider,
                warnings=warnings + ["No rules generated - no matching templates found"],
            )

        # Generate Terraform files
        full_name = f"{self._config.name_prefix}-{name}"
        files = self._provider.generate_complete_config(rules, full_name)

        # Write files if output directory specified
        if self._config.output_dir:
            self._write_files(files)

        return GenerationResult(
            files=files,
            rules_count=len(rules),
            cves_covered=list(covered_cves),
            templates_used=[t.template_id for t in templates],
            provider=self._config.provider,
            warnings=warnings,
        )

    def generate_from_analysis(
        self,
        analysis: CVEAnalysisResult,
        name: str = "vuln-protection",
    ) -> GenerationResult:
        """Generate WAF rules from CVE analysis results.

        Args:
            analysis: CVE analysis result.
            name: Base name for generated resources.

        Returns:
            GenerationResult with generated files.
        """
        # Extract CVE IDs from analysis
        cve_ids = [cve.cve_id for cve in analysis.cves]

        return self.generate_from_cves(cve_ids, name)

    def generate_from_templates(
        self,
        template_ids: list[str],
        name: str = "custom-rules",
    ) -> GenerationResult:
        """Generate WAF rules from specific templates.

        Args:
            template_ids: List of template identifiers.
            name: Base name for generated resources.

        Returns:
            GenerationResult with generated files.
        """
        templates: list[RuleTemplate] = []
        warnings: list[str] = []

        for template_id in template_ids:
            template = self._registry.get_template(template_id)
            if template:
                templates.append(template)
            else:
                warnings.append(f"Template not found: {template_id}")

        # Add custom templates
        templates.extend(self._config.custom_templates)

        # Generate rules
        rules = self._templates_to_rules(templates)

        if not rules:
            return GenerationResult(
                files=[],
                rules_count=0,
                cves_covered=[],
                templates_used=[],
                provider=self._config.provider,
                warnings=warnings + ["No rules generated"],
            )

        # Generate Terraform files
        full_name = f"{self._config.name_prefix}-{name}"
        files = self._provider.generate_complete_config(rules, full_name)

        # Write files if output directory specified
        if self._config.output_dir:
            self._write_files(files)

        # Collect covered CVEs
        cves_covered: list[str] = []
        for template in templates:
            cves_covered.extend(template.cve_ids)

        return GenerationResult(
            files=files,
            rules_count=len(rules),
            cves_covered=list(set(cves_covered)),
            templates_used=[t.template_id for t in templates],
            provider=self._config.provider,
            warnings=warnings,
        )

    def generate_owasp_protection(
        self,
        name: str = "owasp-protection",
    ) -> GenerationResult:
        """Generate WAF rules for OWASP Top 10 protection.

        Args:
            name: Base name for generated resources.

        Returns:
            GenerationResult with generated files.
        """
        owasp_categories = [
            AttackCategory.SQL_INJECTION,
            AttackCategory.CROSS_SITE_SCRIPTING,
            AttackCategory.COMMAND_INJECTION,
            AttackCategory.PATH_TRAVERSAL,
            AttackCategory.XXE,
            AttackCategory.SSRF,
            AttackCategory.LDAP_INJECTION,
        ]

        templates: list[RuleTemplate] = []
        for category in owasp_categories:
            templates.extend(self._registry.get_templates_for_category(category))

        # Add custom templates
        templates.extend(self._config.custom_templates)

        # Deduplicate
        seen_ids: set[str] = set()
        unique_templates: list[RuleTemplate] = []
        for template in templates:
            if template.template_id not in seen_ids:
                seen_ids.add(template.template_id)
                unique_templates.append(template)

        # Generate rules
        rules = self._templates_to_rules(unique_templates)

        if not rules:
            return GenerationResult(
                files=[],
                rules_count=0,
                cves_covered=[],
                templates_used=[],
                provider=self._config.provider,
                warnings=["No OWASP rules generated"],
            )

        # Generate Terraform files
        full_name = f"{self._config.name_prefix}-{name}"
        files = self._provider.generate_complete_config(rules, full_name)

        # Write files if output directory specified
        if self._config.output_dir:
            self._write_files(files)

        return GenerationResult(
            files=files,
            rules_count=len(rules),
            cves_covered=[],
            templates_used=[t.template_id for t in unique_templates],
            provider=self._config.provider,
            warnings=[],
        )

    def generate_critical_protection(
        self,
        name: str = "critical-protection",
    ) -> GenerationResult:
        """Generate WAF rules for all critical CVEs.

        Args:
            name: Base name for generated resources.

        Returns:
            GenerationResult with generated files.
        """
        templates = [
            t for t in self._registry.get_all_templates()
            if t.severity == "critical"
        ]

        # Add custom templates
        templates.extend(self._config.custom_templates)

        # Generate rules
        rules = self._templates_to_rules(templates)

        if not rules:
            return GenerationResult(
                files=[],
                rules_count=0,
                cves_covered=[],
                templates_used=[],
                provider=self._config.provider,
                warnings=["No critical rules generated"],
            )

        # Generate Terraform files
        full_name = f"{self._config.name_prefix}-{name}"
        files = self._provider.generate_complete_config(rules, full_name)

        # Write files if output directory specified
        if self._config.output_dir:
            self._write_files(files)

        # Collect covered CVEs
        cves_covered: list[str] = []
        for template in templates:
            cves_covered.extend(template.cve_ids)

        return GenerationResult(
            files=files,
            rules_count=len(rules),
            cves_covered=list(set(cves_covered)),
            templates_used=[t.template_id for t in templates],
            provider=self._config.provider,
            warnings=[],
        )

    def _templates_to_rules(
        self,
        templates: list[RuleTemplate],
    ) -> list[WafRuleDefinition]:
        """Convert templates to rule definitions.

        Args:
            templates: List of rule templates.

        Returns:
            List of WafRuleDefinition instances.
        """
        rules: list[WafRuleDefinition] = []

        for i, template in enumerate(templates):
            # Merge config tags with template
            custom_tags = dict(self._config.tags)

            rule = template.to_rule_definition(
                priority=i + 1,
                mode=self._config.mode,
                custom_tags=custom_tags,
            )
            rules.append(rule)

        return rules

    def _write_files(self, files: list[GeneratedTerraform]) -> None:
        """Write generated Terraform files to disk.

        Args:
            files: List of generated Terraform files.
        """
        if not self._config.output_dir:
            return

        output_path = Path(self._config.output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        for tf_file in files:
            file_path = output_path / tf_file.filename
            file_path.write_text(tf_file.content)

    def list_available_templates(self) -> list[dict]:
        """List all available rule templates.

        Returns:
            List of template info dictionaries.
        """
        templates = self._registry.get_all_templates()
        return [
            {
                "id": t.template_id,
                "name": t.name,
                "description": t.description,
                "category": t.category.value,
                "severity": t.severity,
                "cve_ids": t.cve_ids,
            }
            for t in templates
        ]

    def list_cve_coverage(self) -> dict[str, list[str]]:
        """List CVE coverage by templates.

        Returns:
            Dictionary mapping CVE IDs to template IDs.
        """
        coverage: dict[str, list[str]] = {}

        for template in self._registry.get_all_templates():
            for cve_id in template.cve_ids:
                if cve_id not in coverage:
                    coverage[cve_id] = []
                coverage[cve_id].append(template.template_id)

        return coverage


def generate_waf_rules(
    cve_ids: list[str],
    provider: WafProviderType = WafProviderType.AWS,
    mode: WafRuleMode = WafRuleMode.LOG,
    output_dir: Optional[str] = None,
    name_prefix: str = "blastauri",
) -> GenerationResult:
    """Convenience function to generate WAF rules for CVEs.

    Args:
        cve_ids: List of CVE identifiers.
        provider: WAF provider to use.
        mode: Rule action mode.
        output_dir: Directory to write files (optional).
        name_prefix: Prefix for resource names.

    Returns:
        GenerationResult with generated files.
    """
    config = WafGeneratorConfig(
        provider=provider,
        mode=mode,
        output_dir=output_dir,
        name_prefix=name_prefix,
    )

    generator = WafGenerator(config)
    return generator.generate_from_cves(cve_ids)


def generate_owasp_rules(
    provider: WafProviderType = WafProviderType.AWS,
    mode: WafRuleMode = WafRuleMode.LOG,
    output_dir: Optional[str] = None,
    name_prefix: str = "blastauri",
) -> GenerationResult:
    """Convenience function to generate OWASP protection rules.

    Args:
        provider: WAF provider to use.
        mode: Rule action mode.
        output_dir: Directory to write files (optional).
        name_prefix: Prefix for resource names.

    Returns:
        GenerationResult with generated files.
    """
    config = WafGeneratorConfig(
        provider=provider,
        mode=mode,
        output_dir=output_dir,
        name_prefix=name_prefix,
    )

    generator = WafGenerator(config)
    return generator.generate_owasp_protection()

"""WAF rule generation and lifecycle management.

This module provides WAF rule generation capabilities for:
- AWS WAFv2 (Terraform)
- Cloudflare WAF (Terraform)

Components:
- providers: WAF provider implementations (AWS, Cloudflare)
- rule_templates: Pre-defined rule templates for known CVEs
- generator: Main WAF rule generation orchestrator
"""

from blastauri.waf.generator import (
    GenerationResult,
    WafGenerator,
    WafGeneratorConfig,
    generate_owasp_rules,
    generate_waf_rules,
)
from blastauri.waf.providers.aws import AwsWafProvider
from blastauri.waf.providers.base import (
    BaseWafProvider,
    GeneratedTerraform,
    WafProviderType,
    WafRuleConfig,
    WafRuleDefinition,
    WafRuleMode,
    WafRuleStatement,
    WafScope,
)
from blastauri.waf.providers.cloudflare import CloudflareWafProvider
from blastauri.waf.lifecycle import (
    LifecycleAnalysis,
    LifecycleChange,
    RuleTrigger,
    WafLifecycleManager,
    WafRuleState,
    WafState,
)
from blastauri.waf.rule_templates import (
    AttackCategory,
    RuleTemplate,
    RuleTemplateRegistry,
    get_all_critical_templates,
    get_default_registry,
    get_owasp_top10_templates,
    get_templates_for_cves,
)

__all__ = [
    # Generator
    "GenerationResult",
    "WafGenerator",
    "WafGeneratorConfig",
    "generate_owasp_rules",
    "generate_waf_rules",
    # Providers
    "AwsWafProvider",
    "BaseWafProvider",
    "CloudflareWafProvider",
    # Base types
    "GeneratedTerraform",
    "WafProviderType",
    "WafRuleConfig",
    "WafRuleDefinition",
    "WafRuleMode",
    "WafRuleStatement",
    "WafScope",
    # Lifecycle
    "LifecycleAnalysis",
    "LifecycleChange",
    "RuleTrigger",
    "WafLifecycleManager",
    "WafRuleState",
    "WafState",
    # Rule templates
    "AttackCategory",
    "RuleTemplate",
    "RuleTemplateRegistry",
    "get_all_critical_templates",
    "get_default_registry",
    "get_owasp_top10_templates",
    "get_templates_for_cves",
]

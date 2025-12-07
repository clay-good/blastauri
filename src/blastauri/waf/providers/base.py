"""Base WAF provider interface."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum


class WafProviderType(str, Enum):
    """Supported WAF providers."""

    AWS = "aws"
    CLOUDFLARE = "cloudflare"


class WafRuleMode(str, Enum):
    """WAF rule action mode."""

    LOG = "log"  # COUNT in AWS, log in Cloudflare
    BLOCK = "block"  # BLOCK in AWS, block in Cloudflare


class WafScope(str, Enum):
    """AWS WAF scope."""

    REGIONAL = "REGIONAL"
    CLOUDFRONT = "CLOUDFRONT"


@dataclass
class WafRuleConfig:
    """Configuration for a WAF rule."""

    rule_id: str
    name: str
    description: str
    priority: int
    mode: WafRuleMode = WafRuleMode.LOG
    cve_ids: list[str] = field(default_factory=list)
    pattern_id: str = ""
    tags: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Add default tags."""
        if "ManagedBy" not in self.tags:
            self.tags["ManagedBy"] = "blastauri"


@dataclass
class WafRuleStatement:
    """A WAF rule statement/condition."""

    field_type: str  # header, body, uri, query_string
    field_name: str | None = None  # For headers
    match_type: str = "contains"  # contains, regex, exact
    patterns: list[str] = field(default_factory=list)
    transformations: list[str] = field(default_factory=list)  # lowercase, url_decode
    negate: bool = False


@dataclass
class WafRuleDefinition:
    """Complete WAF rule definition."""

    config: WafRuleConfig
    statements: list[WafRuleStatement] = field(default_factory=list)
    logic: str = "or"  # and, or


@dataclass
class GeneratedTerraform:
    """Generated Terraform output."""

    filename: str
    content: str
    provider: WafProviderType


class BaseWafProvider(ABC):
    """Base class for WAF providers."""

    provider_type: WafProviderType

    def __init__(
        self,
        mode: WafRuleMode = WafRuleMode.LOG,
        scope: WafScope = WafScope.REGIONAL,
        name_prefix: str = "blastauri",
    ):
        """Initialize the WAF provider.

        Args:
            mode: Default rule mode (log or block).
            scope: AWS WAF scope (regional or cloudfront).
            name_prefix: Prefix for generated resource names.
        """
        self._mode = mode
        self._scope = scope
        self._name_prefix = name_prefix

    @abstractmethod
    def generate_rule(
        self,
        rule_def: WafRuleDefinition,
    ) -> str:
        """Generate Terraform for a single rule.

        Args:
            rule_def: Rule definition.

        Returns:
            Terraform HCL string.
        """
        pass

    @abstractmethod
    def generate_rule_group(
        self,
        name: str,
        rules: list[WafRuleDefinition],
        description: str = "",
    ) -> str:
        """Generate Terraform for a rule group.

        Args:
            name: Rule group name.
            rules: List of rule definitions.
            description: Rule group description.

        Returns:
            Terraform HCL string.
        """
        pass

    @abstractmethod
    def generate_web_acl(
        self,
        name: str,
        rule_group_arns: list[str],
        description: str = "",
    ) -> str:
        """Generate Terraform for a web ACL.

        Args:
            name: Web ACL name.
            rule_group_arns: ARNs of rule groups to include.
            description: Web ACL description.

        Returns:
            Terraform HCL string.
        """
        pass

    def generate_complete_config(
        self,
        rules: list[WafRuleDefinition],
        name: str = "blastauri-waf",
    ) -> list[GeneratedTerraform]:
        """Generate complete Terraform configuration.

        Args:
            rules: List of rule definitions.
            name: Base name for resources.

        Returns:
            List of generated Terraform files.
        """
        outputs: list[GeneratedTerraform] = []

        # Generate main configuration
        main_tf = self._generate_main_config(rules, name)
        outputs.append(
            GeneratedTerraform(
                filename="main.tf",
                content=main_tf,
                provider=self.provider_type,
            )
        )

        # Generate variables
        variables_tf = self._generate_variables()
        outputs.append(
            GeneratedTerraform(
                filename="variables.tf",
                content=variables_tf,
                provider=self.provider_type,
            )
        )

        # Generate outputs
        outputs_tf = self._generate_outputs(name)
        outputs.append(
            GeneratedTerraform(
                filename="outputs.tf",
                content=outputs_tf,
                provider=self.provider_type,
            )
        )

        return outputs

    @abstractmethod
    def _generate_main_config(
        self,
        rules: list[WafRuleDefinition],
        name: str,
    ) -> str:
        """Generate main Terraform configuration."""
        pass

    @abstractmethod
    def _generate_variables(self) -> str:
        """Generate Terraform variables."""
        pass

    @abstractmethod
    def _generate_outputs(self, name: str) -> str:
        """Generate Terraform outputs."""
        pass

    def _sanitize_name(self, name: str) -> str:
        """Sanitize a name for use in Terraform resources.

        Args:
            name: Original name.

        Returns:
            Sanitized name.
        """
        # Replace invalid characters
        sanitized = name.lower()
        sanitized = sanitized.replace(".", "-")
        sanitized = sanitized.replace("_", "-")
        sanitized = sanitized.replace(" ", "-")

        # Remove consecutive dashes
        while "--" in sanitized:
            sanitized = sanitized.replace("--", "-")

        # Remove leading/trailing dashes
        sanitized = sanitized.strip("-")

        return sanitized

    def _escape_hcl_string(self, value: str) -> str:
        """Escape a string for HCL.

        Args:
            value: Original string.

        Returns:
            Escaped string.
        """
        return value.replace("\\", "\\\\").replace('"', '\\"')

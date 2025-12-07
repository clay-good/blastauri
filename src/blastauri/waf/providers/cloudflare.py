"""Cloudflare WAF Terraform generation."""


from blastauri.waf.providers.base import (
    BaseWafProvider,
    WafProviderType,
    WafRuleDefinition,
    WafRuleMode,
    WafRuleStatement,
    WafScope,
)


class CloudflareWafProvider(BaseWafProvider):
    """Cloudflare WAF Terraform provider using rulesets."""

    provider_type = WafProviderType.CLOUDFLARE

    # Mapping of field types to Cloudflare wirefilter fields
    FIELD_MAPPING = {
        "uri": "http.request.uri.path",
        "query_string": "http.request.uri.query",
        "body": "http.request.body.raw",
        "header": "http.request.headers",
        "headers": "http.request.headers",
        "cookies": "http.request.cookies",
        "method": "http.request.method",
        "user_agent": "http.user_agent",
        "ip": "ip.src",
        "country": "ip.geoip.country",
    }

    # Mapping of transformations to Cloudflare functions
    TRANSFORMATION_MAPPING = {
        "lowercase": "lower",
        "url_decode": "url_decode",
        "html_entity_decode": "html_decode",
        "base64_decode": "base64_decode",
        "none": None,
    }

    def __init__(
        self,
        mode: WafRuleMode = WafRuleMode.LOG,
        scope: WafScope = WafScope.REGIONAL,
        name_prefix: str = "blastauri",
        zone_id_var: str = "var.cloudflare_zone_id",
    ):
        """Initialize the Cloudflare WAF provider.

        Args:
            mode: Default rule mode (log or block).
            scope: WAF scope (not used for Cloudflare, kept for compatibility).
            name_prefix: Prefix for generated resource names.
            zone_id_var: Terraform variable reference for zone ID.
        """
        super().__init__(mode, scope, name_prefix)
        self._zone_id_var = zone_id_var

    def generate_rule(
        self,
        rule_def: WafRuleDefinition,
    ) -> str:
        """Generate Terraform for a single Cloudflare WAF rule.

        Args:
            rule_def: Rule definition.

        Returns:
            Terraform HCL string for a rule block.
        """
        config = rule_def.config
        statements = rule_def.statements

        # Generate wirefilter expression
        expression = self._generate_expression(statements, rule_def.logic)

        # Determine action based on mode
        if config.mode == WafRuleMode.BLOCK:
            action = "block"
        else:
            action = "log"

        # Build description with CVE info
        description = config.description
        if config.cve_ids:
            cve_str = ", ".join(config.cve_ids[:3])
            description = f"{description} (CVEs: {cve_str})"

        rule_hcl = f'''
    rules {{
      action      = "{action}"
      expression  = "{self._escape_hcl_string(expression)}"
      description = "{self._escape_hcl_string(description)}"
      enabled     = true
    }}'''

        return rule_hcl

    def _generate_expression(
        self,
        statements: list[WafRuleStatement],
        logic: str,
    ) -> str:
        """Generate Cloudflare wirefilter expression.

        Args:
            statements: List of rule statements.
            logic: Logic operator (and/or).

        Returns:
            Wirefilter expression string.
        """
        if not statements:
            return "false"

        expressions = [self._generate_single_expression(s) for s in statements]

        if len(expressions) == 1:
            return expressions[0]

        # Join with appropriate operator
        operator = " or " if logic == "or" else " and "
        return f"({operator.join(expressions)})"

    def _generate_single_expression(self, statement: WafRuleStatement) -> str:
        """Generate a single wirefilter expression.

        Args:
            statement: Rule statement.

        Returns:
            Wirefilter expression string.
        """
        field_type = statement.field_type.lower()
        cf_field = self.FIELD_MAPPING.get(field_type, field_type)

        # Handle header fields specially
        if field_type == "header" and statement.field_name:
            cf_field = f'http.request.headers["{statement.field_name.lower()}"]'

        # Apply transformations
        field_expr = self._apply_transformations(cf_field, statement.transformations)

        # Generate match expression based on type
        if statement.match_type == "regex":
            return self._generate_regex_expression(
                field_expr, statement.patterns, statement.negate
            )
        elif statement.match_type == "exact":
            return self._generate_exact_expression(
                field_expr, statement.patterns, statement.negate
            )
        else:  # contains
            return self._generate_contains_expression(
                field_expr, statement.patterns, statement.negate
            )

    def _apply_transformations(
        self,
        field: str,
        transformations: list[str],
    ) -> str:
        """Apply transformations to a field expression.

        Args:
            field: Base field expression.
            transformations: List of transformations to apply.

        Returns:
            Transformed field expression.
        """
        result = field

        for t in transformations:
            cf_func = self.TRANSFORMATION_MAPPING.get(t)
            if cf_func:
                result = f"{cf_func}({result})"

        return result

    def _generate_regex_expression(
        self,
        field: str,
        patterns: list[str],
        negate: bool,
    ) -> str:
        """Generate regex match expression.

        Args:
            field: Field expression.
            patterns: Regex patterns to match.
            negate: Whether to negate the match.

        Returns:
            Wirefilter expression.
        """
        if not patterns:
            return "false"

        # Use first pattern (Cloudflare supports one pattern per expression)
        pattern = patterns[0]
        operator = "~" if not negate else "!~"

        return f'{field} {operator} "{self._escape_wirefilter_string(pattern)}"'

    def _generate_exact_expression(
        self,
        field: str,
        patterns: list[str],
        negate: bool,
    ) -> str:
        """Generate exact match expression.

        Args:
            field: Field expression.
            patterns: Patterns to match exactly.
            negate: Whether to negate the match.

        Returns:
            Wirefilter expression.
        """
        if not patterns:
            return "false"

        if len(patterns) == 1:
            operator = "eq" if not negate else "ne"
            return f'{field} {operator} "{self._escape_wirefilter_string(patterns[0])}"'

        # Multiple patterns - use 'in' operator
        escaped_patterns = [
            f'"{self._escape_wirefilter_string(p)}"' for p in patterns
        ]
        operator = "in" if not negate else "not in"
        return f'{field} {operator} {{{" ".join(escaped_patterns)}}}'

    def _generate_contains_expression(
        self,
        field: str,
        patterns: list[str],
        negate: bool,
    ) -> str:
        """Generate contains match expression.

        Args:
            field: Field expression.
            patterns: Patterns to search for.
            negate: Whether to negate the match.

        Returns:
            Wirefilter expression.
        """
        if not patterns:
            return "false"

        if len(patterns) == 1:
            operator = "contains" if not negate else "not contains"
            return f'{field} {operator} "{self._escape_wirefilter_string(patterns[0])}"'

        # Multiple patterns - combine with or
        exprs = []
        operator = "contains" if not negate else "not contains"
        for p in patterns:
            exprs.append(f'{field} {operator} "{self._escape_wirefilter_string(p)}"')

        join_op = " or " if not negate else " and "
        return f"({join_op.join(exprs)})"

    def _escape_wirefilter_string(self, value: str) -> str:
        """Escape a string for wirefilter expressions.

        Args:
            value: Original string.

        Returns:
            Escaped string.
        """
        # Escape backslashes and quotes
        return value.replace("\\", "\\\\").replace('"', '\\"')

    def generate_rule_group(
        self,
        name: str,
        rules: list[WafRuleDefinition],
        description: str = "",
    ) -> str:
        """Generate Terraform for a Cloudflare WAF ruleset.

        Args:
            name: Ruleset name.
            rules: List of rule definitions.
            description: Ruleset description.

        Returns:
            Terraform HCL string.
        """
        sanitized_name = self._sanitize_name(name)

        # Generate rules
        rules_hcl = "\n".join(self.generate_rule(r) for r in rules)

        return f'''resource "cloudflare_ruleset" "{sanitized_name}" {{
  zone_id     = {self._zone_id_var}
  name        = "{self._escape_hcl_string(name)}"
  description = "{self._escape_hcl_string(description or f'Blastauri WAF rules for {name}')}"
  kind        = "zone"
  phase       = "http_request_firewall_custom"

{rules_hcl}
}}
'''

    def generate_web_acl(
        self,
        name: str,
        rule_group_arns: list[str],
        description: str = "",
    ) -> str:
        """Generate Terraform for Cloudflare WAF configuration.

        Note: Cloudflare uses rulesets instead of ACLs. This method
        generates a reference configuration for consistency with the
        base interface.

        Args:
            name: Configuration name.
            rule_group_arns: Ruleset references (resource names).
            description: Configuration description.

        Returns:
            Terraform HCL string with comments.
        """
        sanitized_name = self._sanitize_name(name)

        # Generate ruleset references as a local variable
        ruleset_refs = [f'cloudflare_ruleset.{ref}.id' for ref in rule_group_arns]
        refs_list = ", ".join(ruleset_refs)

        return f'''# Cloudflare WAF Configuration
# Note: Cloudflare uses rulesets instead of Web ACLs
# Rulesets are automatically applied to the zone

locals {{
  {sanitized_name}_ruleset_ids = [{refs_list}]
}}

# Output the ruleset IDs for reference
output "{sanitized_name}_rulesets" {{
  description = "Cloudflare ruleset IDs for {name}"
  value       = local.{sanitized_name}_ruleset_ids
}}
'''

    def _generate_main_config(
        self,
        rules: list[WafRuleDefinition],
        name: str,
    ) -> str:
        """Generate main Terraform configuration for Cloudflare WAF.

        Args:
            rules: List of rule definitions.
            name: Base name for resources.

        Returns:
            Terraform HCL string.
        """
        sanitized_name = self._sanitize_name(name)

        # Provider configuration
        provider_hcl = '''terraform {
  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 4.0"
    }
  }
}

provider "cloudflare" {
  api_token = var.cloudflare_api_token
}

'''

        # Generate main ruleset
        ruleset_hcl = self.generate_rule_group(
            f"{name}-rules",
            rules,
            "Blastauri WAF rules for vulnerability protection",
        )

        # Generate configuration output
        config_output = self.generate_web_acl(
            name,
            [f"{sanitized_name}-rules"],
            "Blastauri WAF Configuration",
        )

        return provider_hcl + ruleset_hcl + "\n" + config_output

    def _generate_variables(self) -> str:
        """Generate Terraform variables for Cloudflare WAF.

        Returns:
            Terraform HCL string for variables.
        """
        return '''variable "cloudflare_api_token" {
  description = "Cloudflare API token with WAF permissions"
  type        = string
  sensitive   = true
}

variable "cloudflare_zone_id" {
  description = "Cloudflare Zone ID to apply WAF rules"
  type        = string
}

variable "environment" {
  description = "Environment name for tagging"
  type        = string
  default     = "production"
}
'''

    def _generate_outputs(self, name: str) -> str:
        """Generate Terraform outputs for Cloudflare WAF.

        Args:
            name: Base name for resources.

        Returns:
            Terraform HCL string for outputs.
        """
        sanitized_name = self._sanitize_name(name)

        return f'''output "ruleset_id" {{
  description = "ID of the Cloudflare WAF ruleset"
  value       = cloudflare_ruleset.{sanitized_name}-rules.id
}}

output "zone_id" {{
  description = "Cloudflare Zone ID"
  value       = var.cloudflare_zone_id
}}
'''

    def generate_managed_ruleset_override(
        self,
        name: str,
        managed_ruleset_id: str,
        disabled_rules: list[str] = None,
        overridden_rules: dict[str, str] = None,
    ) -> str:
        """Generate Terraform for a managed ruleset override.

        This allows customizing Cloudflare's managed WAF rulesets.

        Args:
            name: Override name.
            managed_ruleset_id: ID of the managed ruleset to override.
            disabled_rules: List of rule IDs to disable.
            overridden_rules: Dict of rule ID to action overrides.

        Returns:
            Terraform HCL string.
        """
        sanitized_name = self._sanitize_name(name)
        disabled_rules = disabled_rules or []
        overridden_rules = overridden_rules or {}

        # Generate rule overrides
        override_blocks = []

        for rule_id in disabled_rules:
            override_blocks.append(f'''
    rules {{
      id      = "{rule_id}"
      enabled = false
    }}''')

        for rule_id, action in overridden_rules.items():
            override_blocks.append(f'''
    rules {{
      id     = "{rule_id}"
      action = "{action}"
    }}''')

        rules_hcl = "\n".join(override_blocks) if override_blocks else ""

        return f'''resource "cloudflare_ruleset" "{sanitized_name}_override" {{
  zone_id     = {self._zone_id_var}
  name        = "{self._escape_hcl_string(name)} Override"
  description = "Override configuration for managed ruleset"
  kind        = "zone"
  phase       = "http_request_firewall_managed"

  rules {{
    action = "execute"
    action_parameters {{
      id = "{managed_ruleset_id}"
      overrides {{{rules_hcl}
      }}
    }}
    expression  = "true"
    description = "Execute managed ruleset with overrides"
    enabled     = true
  }}
}}
'''

    def generate_rate_limit_rule(
        self,
        name: str,
        requests_per_period: int,
        period: int = 60,
        expression: str = "true",
        action: str = "block",
        mitigation_timeout: int = 60,
    ) -> str:
        """Generate Terraform for a rate limiting rule.

        Args:
            name: Rule name.
            requests_per_period: Maximum requests allowed.
            period: Time period in seconds.
            expression: Wirefilter expression for matching.
            action: Action to take (block, challenge, log).
            mitigation_timeout: How long to block in seconds.

        Returns:
            Terraform HCL string.
        """
        sanitized_name = self._sanitize_name(name)

        return f'''resource "cloudflare_ruleset" "{sanitized_name}_rate_limit" {{
  zone_id     = {self._zone_id_var}
  name        = "{self._escape_hcl_string(name)} Rate Limit"
  description = "Rate limiting rule: {requests_per_period} requests per {period}s"
  kind        = "zone"
  phase       = "http_ratelimit"

  rules {{
    action = "{action}"
    ratelimit {{
      characteristics     = ["ip.src", "cf.colo.id"]
      period              = {period}
      requests_per_period = {requests_per_period}
      mitigation_timeout  = {mitigation_timeout}
    }}
    expression  = "{self._escape_hcl_string(expression)}"
    description = "Rate limit: {requests_per_period} req/{period}s"
    enabled     = true
  }}
}}
'''

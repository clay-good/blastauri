"""AWS WAF Terraform generation."""


from blastauri.waf.providers.base import (
    BaseWafProvider,
    WafProviderType,
    WafRuleDefinition,
    WafRuleMode,
    WafRuleStatement,
)


class AwsWafProvider(BaseWafProvider):
    """AWS WAFv2 Terraform provider."""

    provider_type = WafProviderType.AWS

    # Mapping of field types to AWS WAF field names
    FIELD_MAPPING = {
        "uri": "uri_path",
        "query_string": "query_string",
        "body": "body",
        "header": "single_header",
        "headers": "headers",
        "cookies": "cookies",
        "method": "method",
    }

    # Mapping of transformations to AWS WAF text transformations
    TRANSFORMATION_MAPPING = {
        "lowercase": "LOWERCASE",
        "url_decode": "URL_DECODE",
        "html_entity_decode": "HTML_ENTITY_DECODE",
        "compress_whitespace": "COMPRESS_WHITE_SPACE",
        "base64_decode": "BASE64_DECODE",
        "none": "NONE",
    }

    def generate_rule(
        self,
        rule_def: WafRuleDefinition,
    ) -> str:
        """Generate Terraform for a single AWS WAF rule."""
        config = rule_def.config
        statements = rule_def.statements

        # Generate statement block
        statement_hcl = self._generate_statement(statements, rule_def.logic)

        # Determine action based on mode
        if config.mode == WafRuleMode.BLOCK:
            action = "block {}"
        else:
            action = "count {}"

        rule_hcl = f'''
  rule {{
    name     = "{self._escape_hcl_string(config.name)}"
    priority = {config.priority}

    action {{
      {action}
    }}

    statement {{
      {statement_hcl}
    }}

    visibility_config {{
      cloudwatch_metrics_enabled = true
      metric_name                = "{self._sanitize_name(config.name)}"
      sampled_requests_enabled   = true
    }}
  }}
'''
        return rule_hcl

    def _generate_statement(
        self,
        statements: list[WafRuleStatement],
        logic: str,
    ) -> str:
        """Generate AWS WAF statement HCL."""
        if not statements:
            return ""

        if len(statements) == 1:
            return self._generate_single_statement(statements[0])

        # Multiple statements - use or_statement or and_statement
        statement_type = "or_statement" if logic == "or" else "and_statement"

        inner_statements = "\n".join(
            f"      statement {{\n        {self._generate_single_statement(s)}\n      }}"
            for s in statements
        )

        return f'''{statement_type} {{
{inner_statements}
    }}'''

    def _generate_single_statement(self, statement: WafRuleStatement) -> str:
        """Generate a single statement block."""
        # Get field to match
        field_hcl = self._generate_field_to_match(statement)

        # Get transformations
        transforms_hcl = self._generate_text_transformations(statement.transformations)

        # Determine match type
        if statement.match_type == "regex":
            return self._generate_regex_statement(statement, field_hcl, transforms_hcl)
        elif statement.match_type == "exact":
            return self._generate_byte_match_statement(
                statement, field_hcl, transforms_hcl, "EXACTLY"
            )
        else:  # contains
            return self._generate_byte_match_statement(
                statement, field_hcl, transforms_hcl, "CONTAINS"
            )

    def _generate_field_to_match(self, statement: WafRuleStatement) -> str:
        """Generate field_to_match block."""
        field_type = statement.field_type.lower()
        aws_field = self.FIELD_MAPPING.get(field_type, field_type)

        if field_type == "header" and statement.field_name:
            return f'''field_to_match {{
          single_header {{
            name = "{statement.field_name.lower()}"
          }}
        }}'''
        elif field_type == "body":
            return '''field_to_match {
          body {
            oversize_handling = "CONTINUE"
          }
        }'''
        elif field_type == "uri":
            return '''field_to_match {
          uri_path {}
        }'''
        elif field_type == "query_string":
            return '''field_to_match {
          query_string {}
        }'''
        else:
            return f'''field_to_match {{
          {aws_field} {{}}
        }}'''

    def _generate_text_transformations(
        self,
        transformations: list[str],
    ) -> str:
        """Generate text_transformation blocks."""
        if not transformations:
            transformations = ["none"]

        transform_blocks = []
        for i, t in enumerate(transformations):
            aws_transform = self.TRANSFORMATION_MAPPING.get(t, "NONE")
            transform_blocks.append(
                f'''text_transformation {{
          priority = {i}
          type     = "{aws_transform}"
        }}'''
            )

        return "\n        ".join(transform_blocks)

    def _generate_byte_match_statement(
        self,
        statement: WafRuleStatement,
        field_hcl: str,
        transforms_hcl: str,
        positional_constraint: str,
    ) -> str:
        """Generate byte_match_statement block."""
        # Use first pattern
        pattern = statement.patterns[0] if statement.patterns else ""

        return f'''byte_match_statement {{
        search_string         = "{self._escape_hcl_string(pattern)}"
        positional_constraint = "{positional_constraint}"

        {field_hcl}

        {transforms_hcl}
      }}'''

    def _generate_regex_statement(
        self,
        statement: WafRuleStatement,
        field_hcl: str,
        transforms_hcl: str,
    ) -> str:
        """Generate regex_pattern_set_reference_statement block."""
        # For regex, we need to create a regex pattern set
        # This generates a reference to a pattern set that must be defined elsewhere
        pattern_set_arn = f"aws_wafv2_regex_pattern_set.{self._sanitize_name(statement.field_type)}_patterns.arn"

        return f'''regex_pattern_set_reference_statement {{
        arn = {pattern_set_arn}

        {field_hcl}

        {transforms_hcl}
      }}'''

    def _generate_tags(
        self,
        tags: dict[str, str],
        cve_ids: list[str],
    ) -> str:
        """Generate tags block."""
        all_tags = dict(tags)
        if cve_ids:
            all_tags["CVEs"] = ",".join(cve_ids[:5])  # Limit to 5 CVEs in tag

        tag_lines = [f'    {k} = "{v}"' for k, v in all_tags.items()]
        return "tags = {\n" + "\n".join(tag_lines) + "\n  }"

    def generate_rule_group(
        self,
        name: str,
        rules: list[WafRuleDefinition],
        description: str = "",
    ) -> str:
        """Generate Terraform for an AWS WAF rule group."""
        sanitized_name = self._sanitize_name(name)

        # Generate rules
        rules_hcl = "\n".join(self.generate_rule(r) for r in rules)

        # Calculate capacity (simplified - real calculation would be more complex)
        capacity = len(rules) * 50  # Approximate capacity per rule

        # Collect all CVE IDs for tags
        all_cve_ids: list[str] = []
        for rule in rules:
            all_cve_ids.extend(rule.config.cve_ids)

        tags_hcl = self._generate_tags(
            {"Name": name, "ManagedBy": "blastauri"},
            list(set(all_cve_ids)),
        )

        return f'''resource "aws_wafv2_rule_group" "{sanitized_name}" {{
  name        = "{self._escape_hcl_string(name)}"
  description = "{self._escape_hcl_string(description or f'Blastauri WAF rules for {name}')}"
  scope       = var.waf_scope
  capacity    = {capacity}

{rules_hcl}

  visibility_config {{
    cloudwatch_metrics_enabled = true
    metric_name                = "{sanitized_name}"
    sampled_requests_enabled   = true
  }}

  {tags_hcl}
}}
'''

    def generate_web_acl(
        self,
        name: str,
        rule_group_arns: list[str],
        description: str = "",
    ) -> str:
        """Generate Terraform for an AWS WAF web ACL."""
        sanitized_name = self._sanitize_name(name)

        # Generate rule group references
        rule_refs = []
        for i, arn in enumerate(rule_group_arns):
            rule_refs.append(f'''
  rule {{
    name     = "rule-group-{i}"
    priority = {i + 1}

    override_action {{
      none {{}}
    }}

    statement {{
      rule_group_reference_statement {{
        arn = {arn}
      }}
    }}

    visibility_config {{
      cloudwatch_metrics_enabled = true
      metric_name                = "rule-group-{i}"
      sampled_requests_enabled   = true
    }}
  }}
''')

        rules_hcl = "\n".join(rule_refs)

        return f'''resource "aws_wafv2_web_acl" "{sanitized_name}" {{
  name        = "{self._escape_hcl_string(name)}"
  description = "{self._escape_hcl_string(description or 'Blastauri WAF Web ACL')}"
  scope       = var.waf_scope

  default_action {{
    allow {{}}
  }}

{rules_hcl}

  visibility_config {{
    cloudwatch_metrics_enabled = true
    metric_name                = "{sanitized_name}"
    sampled_requests_enabled   = true
  }}

  tags = {{
    Name      = "{self._escape_hcl_string(name)}"
    ManagedBy = "blastauri"
  }}
}}
'''

    def _generate_main_config(
        self,
        rules: list[WafRuleDefinition],
        name: str,
    ) -> str:
        """Generate main Terraform configuration for AWS WAF."""
        sanitized_name = self._sanitize_name(name)

        # Provider configuration
        provider_hcl = '''terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

'''

        # Generate regex pattern sets if needed
        regex_rules = [
            r for r in rules
            if any(s.match_type == "regex" for s in r.statements)
        ]

        regex_sets_hcl = ""
        for rule in regex_rules:
            for stmt in rule.statements:
                if stmt.match_type == "regex" and stmt.patterns:
                    set_name = f"{sanitized_name}-{self._sanitize_name(stmt.field_type)}"
                    patterns_hcl = "\n".join(
                        f'  regular_expression {{\n    regex_string = "{self._escape_hcl_string(p)}"\n  }}'
                        for p in stmt.patterns
                    )
                    regex_sets_hcl += f'''
resource "aws_wafv2_regex_pattern_set" "{self._sanitize_name(stmt.field_type)}_patterns" {{
  name        = "{set_name}-patterns"
  description = "Regex patterns for {stmt.field_type}"
  scope       = var.waf_scope

{patterns_hcl}

  tags = {{
    ManagedBy = "blastauri"
  }}
}}

'''

        # Generate rule group
        rule_group_hcl = self.generate_rule_group(
            f"{name}-rules",
            rules,
            "Blastauri WAF rules for vulnerability protection",
        )

        # Generate web ACL
        web_acl_hcl = self.generate_web_acl(
            name,
            [f"aws_wafv2_rule_group.{sanitized_name}-rules.arn"],
            "Blastauri WAF Web ACL",
        )

        return provider_hcl + regex_sets_hcl + rule_group_hcl + "\n" + web_acl_hcl

    def _generate_variables(self) -> str:
        """Generate Terraform variables for AWS WAF."""
        return '''variable "aws_region" {
  description = "AWS region for WAF resources"
  type        = string
  default     = "us-east-1"
}

variable "waf_scope" {
  description = "WAF scope: REGIONAL or CLOUDFRONT"
  type        = string
  default     = "REGIONAL"

  validation {
    condition     = contains(["REGIONAL", "CLOUDFRONT"], var.waf_scope)
    error_message = "WAF scope must be REGIONAL or CLOUDFRONT."
  }
}

variable "environment" {
  description = "Environment name for tagging"
  type        = string
  default     = "production"
}
'''

    def _generate_outputs(self, name: str) -> str:
        """Generate Terraform outputs for AWS WAF."""
        sanitized_name = self._sanitize_name(name)

        return f'''output "web_acl_arn" {{
  description = "ARN of the WAF Web ACL"
  value       = aws_wafv2_web_acl.{sanitized_name}.arn
}}

output "web_acl_id" {{
  description = "ID of the WAF Web ACL"
  value       = aws_wafv2_web_acl.{sanitized_name}.id
}}

output "rule_group_arn" {{
  description = "ARN of the WAF rule group"
  value       = aws_wafv2_rule_group.{sanitized_name}-rules.arn
}}

output "rule_group_id" {{
  description = "ID of the WAF rule group"
  value       = aws_wafv2_rule_group.{sanitized_name}-rules.id
}}
'''

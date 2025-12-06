# WAF Rule Management

Blastauri generates and manages Web Application Firewall (WAF) rules to protect against known vulnerabilities detected in your dependencies.

## Overview

The WAF module provides:

- **Rule Generation**: Generate Terraform configurations for AWS WAF or Cloudflare WAF
- **Lifecycle Management**: Track rule states, promote from log to block mode, remove obsolete rules
- **Template Library**: Pre-built rule templates for critical CVEs and OWASP Top 10

## Supported Providers

### AWS WAFv2

Generates Terraform configurations for AWS WAFv2:
- Rule groups with custom rules
- Web ACLs for CloudFront or regional resources
- Support for REGIONAL and CLOUDFRONT scopes

### Cloudflare WAF

Generates Terraform configurations for Cloudflare:
- Custom rulesets with firewall rules
- Rate limiting rules
- Support for expression-based matching

## Commands

### Generate Rules

Generate WAF rules from detected CVEs:

```bash
# Generate rules for scanned dependencies
blastauri waf generate ./my-project

# Generate for specific CVEs
blastauri waf generate ./my-project --cves CVE-2021-44228,CVE-2022-22965

# Generate OWASP Top 10 protection
blastauri waf generate ./my-project --owasp

# Generate for Cloudflare
blastauri waf generate ./my-project --provider cloudflare

# Output to specific directory
blastauri waf generate ./my-project --output-dir ./terraform/waf

# Generate in block mode instead of log
blastauri waf generate ./my-project --mode block
```

### Sync Rules

Synchronize WAF rules with your repository:

```bash
# Sync rules and create MR/PR
blastauri waf sync --project mygroup/myproject --create-mr

# Sync with GitHub
blastauri waf sync --repo owner/repo --create-pr

# Sync without creating MR
blastauri waf sync --project mygroup/myproject
```

### Check Status

View current WAF rule status:

```bash
# Show status summary
blastauri waf status

# Show detailed rule list
blastauri waf status --details
```

### List Templates

View available rule templates:

```bash
# List all templates
blastauri waf templates

# List templates for specific category
blastauri waf templates --category sqli

# List templates for specific CVE
blastauri waf templates --cve CVE-2021-44228
```

## Rule Lifecycle

### States

WAF rules transition through these states:

1. **Pending**: Rule generated but not yet deployed
2. **Log Mode**: Rule deployed in monitoring mode (counts but doesn't block)
3. **Block Mode**: Rule actively blocking matching requests
4. **Obsolete**: Vulnerability fixed in dependencies, rule marked for removal

### Promotion Flow

```
Pending -> Log Mode -> Block Mode
              |
              v
          Obsolete (when dependency patched)
```

### State File

Blastauri tracks rule state in `.blastauri/waf-state.json`:

```json
{
  "version": 1,
  "last_updated": "2024-01-15T10:30:00Z",
  "rules": {
    "log4shell-jndi": {
      "rule_id": "log4shell-jndi",
      "cve_ids": ["CVE-2021-44228"],
      "mode": "log",
      "created_at": "2024-01-01T00:00:00Z",
      "trigger": {
        "package": "org.apache.logging.log4j:log4j-core",
        "version": "2.14.1",
        "ecosystem": "maven"
      }
    }
  }
}
```

### Automatic Promotion

After the configured `promotion_days` (default: 14 days), rules in log mode are flagged as promotion candidates. Review WAF logs to ensure rules aren't blocking legitimate traffic before promoting to block mode.

### Automatic Removal

When a dependency vulnerability is patched, the corresponding WAF rule is marked as obsolete. The sync command will propose removing these rules.

## Rule Templates

### Critical CVE Templates

Pre-built templates for high-profile vulnerabilities:

| Template | CVEs | Description |
|----------|------|-------------|
| `log4shell-jndi` | CVE-2021-44228, CVE-2021-45046 | Log4j JNDI injection |
| `spring4shell` | CVE-2022-22965 | Spring Framework RCE |
| `struts-ognl` | CVE-2017-5638 | Apache Struts OGNL injection |
| `text4shell` | CVE-2022-42889 | Apache Commons Text RCE |

### OWASP Top 10 Templates

Templates covering OWASP Top 10 attack categories:

| Category | Template IDs |
|----------|-------------|
| SQL Injection | `sqli-basic`, `sqli-union`, `sqli-blind` |
| XSS | `xss-script`, `xss-event`, `xss-data` |
| Command Injection | `cmdi-basic`, `cmdi-shell` |
| Path Traversal | `path-traversal` |
| SSRF | `ssrf-internal`, `ssrf-metadata` |
| XXE | `xxe-entity` |
| LDAP Injection | `ldapi-basic` |

### Custom Templates

Register custom templates programmatically:

```python
from blastauri.waf import RuleTemplateRegistry, RuleTemplate, WafRuleStatement, AttackCategory

registry = RuleTemplateRegistry()

custom_template = RuleTemplate(
    template_id="custom-api-protection",
    name="Custom API Protection",
    description="Block suspicious API requests",
    category=AttackCategory.GENERIC,
    statements=[
        WafRuleStatement(
            field_type="uri",
            match_type="contains",
            patterns=["/api/admin", "/api/internal"],
        )
    ],
)

registry.register(custom_template)
```

## Generated Terraform

### AWS WAFv2 Structure

```
terraform/waf/
  main.tf           # Rule group and Web ACL resources
  variables.tf      # Input variables (scope, prefix)
  outputs.tf        # Outputs (rule group ARN, Web ACL ARN)
```

Example `main.tf`:

```hcl
resource "aws_wafv2_rule_group" "blastauri" {
  name        = "blastauri-rules"
  description = "WAF rules managed by Blastauri"
  scope       = var.scope
  capacity    = 100

  rule {
    name     = "Log4Shell Protection"
    priority = 1

    action {
      count {}
    }

    statement {
      or_statement {
        statement {
          byte_match_statement {
            search_string = "${jndi:"
            field_to_match {
              uri_path {}
            }
            text_transformation {
              priority = 0
              type     = "URL_DECODE"
            }
            positional_constraint = "CONTAINS"
          }
        }
      }
    }

    visibility_config {
      sampled_requests_enabled   = true
      cloudwatch_metrics_enabled = true
      metric_name               = "log4shell-protection"
    }
  }

  visibility_config {
    sampled_requests_enabled   = true
    cloudwatch_metrics_enabled = true
    metric_name               = "blastauri-rules"
  }

  tags = {
    ManagedBy = "blastauri"
  }
}
```

### Cloudflare Structure

```
terraform/waf/
  main.tf           # Ruleset resources
  variables.tf      # Input variables (zone_id)
  outputs.tf        # Outputs (ruleset ID)
```

Example `main.tf`:

```hcl
resource "cloudflare_ruleset" "blastauri" {
  zone_id     = var.zone_id
  name        = "Blastauri WAF Rules"
  description = "WAF rules managed by Blastauri"
  kind        = "zone"
  phase       = "http_request_firewall_custom"

  rules {
    action      = "log"
    expression  = "http.request.uri.path contains \"${jndi:\""
    description = "Log4Shell Protection"
    enabled     = true
  }
}
```

## Integration

### GitLab CI

```yaml
include:
  - remote: 'https://raw.githubusercontent.com/clay-good/blastauri/main/.gitlab/ci/blastauri.yml'

blastauri-waf-sync:
  extends: .blastauri-waf
  variables:
    GITLAB_TOKEN: $CI_JOB_TOKEN
    WAF_PROVIDER: aws
```

### GitHub Actions

```yaml
- uses: clay-good/blastauri@v1
  with:
    command: waf-sync
    waf-provider: aws
    waf-mode: log
    create-mr: true
    github-token: ${{ secrets.GITHUB_TOKEN }}
```

### Manual Workflow

1. Scan dependencies for vulnerabilities
2. Generate WAF rules: `blastauri waf generate .`
3. Review generated Terraform
4. Apply to staging: `terraform apply`
5. Monitor WAF logs for false positives
6. Promote rules to block mode after validation
7. Remove obsolete rules when dependencies are patched

## Best Practices

1. **Start in Log Mode**: Always deploy new rules in log mode first
2. **Monitor Before Blocking**: Review WAF logs for at least 7-14 days
3. **Version Control Terraform**: Commit all generated Terraform files
4. **Use State Tracking**: Let Blastauri track rule state in `.blastauri/waf-state.json`
5. **Regular Sync**: Run `waf sync` in CI to keep rules current
6. **Review Proposals**: Manually review MRs before merging WAF changes

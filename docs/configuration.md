# Configuration

Blastauri uses a YAML configuration file (`.blastauri.yml`) for project-specific settings. Command-line arguments and environment variables can override these settings.

## Configuration File

Create a `.blastauri.yml` file in your repository root:

```yaml
version: 1
platform: gitlab  # or github

analysis:
  ai_provider: none
  severity_threshold: low
  post_comment: true
  apply_labels: true

waf:
  provider: aws
  mode: log
  output_dir: ./terraform/waf
  promotion_days: 14

scanner:
  ecosystems:
    - npm
    - pypi
  exclude_dev: false
  exclude_patterns:
    - node_modules
    - vendor
    - .git

gitlab:
  url: https://gitlab.com

github:
  api_url: https://api.github.com
```

## Configuration Options

### Root Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `version` | integer | 1 | Configuration schema version |
| `platform` | string | gitlab | Primary platform: `gitlab` or `github` |

### Analysis Options

Configure upgrade impact analysis behavior:

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `ai_provider` | string | none | AI provider for enhanced analysis: `none`, `claude`, `augment` |
| `severity_threshold` | string | low | Minimum severity to report: `critical`, `high`, `medium`, `low` |
| `post_comment` | boolean | true | Post analysis results as MR/PR comment |
| `apply_labels` | boolean | true | Apply severity labels to MR/PR |

### WAF Options

Configure WAF rule generation and lifecycle:

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `provider` | string | aws | WAF provider: `aws`, `cloudflare`, `both` |
| `mode` | string | log | Default rule mode: `log` or `block` |
| `output_dir` | string | ./terraform/waf | Output directory for Terraform files |
| `promotion_days` | integer | 14 | Days before suggesting log-to-block promotion |

### Scanner Options

Configure dependency scanning:

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `ecosystems` | list | all | Ecosystems to scan (omit to scan all) |
| `exclude_dev` | boolean | false | Exclude development dependencies |
| `exclude_patterns` | list | [] | Glob patterns to exclude from scanning |

Available ecosystems:
- `npm` - Node.js (package-lock.json, yarn.lock, pnpm-lock.yaml)
- `pypi` - Python (requirements.txt, Pipfile.lock, poetry.lock)
- `go` - Go (go.mod, go.sum)
- `rubygems` - Ruby (Gemfile.lock)
- `maven` - Java (pom.xml)
- `cargo` - Rust (Cargo.lock)
- `composer` - PHP (composer.lock)

### GitLab Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `url` | string | https://gitlab.com | GitLab instance URL |

### GitHub Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `api_url` | string | https://api.github.com | GitHub API URL |

## Environment Variables

Sensitive values should be provided via environment variables:

| Variable | Description |
|----------|-------------|
| `GITLAB_TOKEN` | GitLab API access token |
| `GITHUB_TOKEN` | GitHub API access token |
| `NVD_API_KEY` | NVD API key for CVE lookups (optional, free from NVD) |

### AI Provider Setup (Optional)

If you want to enable AI-assisted review (`ai_provider: claude` or `ai_provider: augment`), you need to install and configure the respective CLI tool:

**For Claude:**
```bash
# Install Claude CLI (see https://claude.ai/cli)
# Configure with your Anthropic API key
claude login
```

**For Augment:**
```bash
# Install Augment CLI (see https://augmentcode.com)
# Configure with your Augment API key
augment login
```

Blastauri calls these CLI tools directly and does NOT require or store any API keys itself.

## Command-Line Overrides

Most configuration options can be overridden via command-line flags:

```bash
# Override severity threshold
blastauri analyze --severity high

# Override WAF provider
blastauri waf generate --provider cloudflare

# Specify custom config file
blastauri --config /path/to/.blastauri.yml analyze
```

## Configuration Validation

Validate your configuration file:

```bash
blastauri config validate
```

Show the current resolved configuration:

```bash
blastauri config show
```

## Configuration Precedence

Configuration values are resolved in this order (highest to lowest priority):

1. Command-line arguments
2. Environment variables
3. Project `.blastauri.yml` file
4. Default values

## Examples

### Minimal Configuration

```yaml
version: 1
platform: gitlab
```

### Full Configuration

```yaml
version: 1
platform: gitlab

analysis:
  ai_provider: claude
  severity_threshold: medium
  post_comment: true
  apply_labels: true

waf:
  provider: both
  mode: log
  output_dir: ./infrastructure/waf
  promotion_days: 7

scanner:
  ecosystems:
    - npm
    - pypi
    - go
  exclude_dev: true
  exclude_patterns:
    - node_modules
    - vendor
    - .git
    - __pycache__
    - "*.test.*"

gitlab:
  url: https://gitlab.example.com

github:
  api_url: https://api.github.com
```

### GitHub-Only Configuration

```yaml
version: 1
platform: github

analysis:
  severity_threshold: high
  post_comment: true
  apply_labels: true

scanner:
  ecosystems:
    - npm
  exclude_dev: false
```

### WAF-Focused Configuration

```yaml
version: 1
platform: gitlab

waf:
  provider: aws
  mode: log
  output_dir: ./terraform/security/waf
  promotion_days: 14

scanner:
  exclude_dev: true
```

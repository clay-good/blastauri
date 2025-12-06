# GitHub Setup Guide

This guide explains how to set up Blastauri for GitHub with Dependabot or Renovate.

## Prerequisites

- GitHub repository with Dependabot or Renovate configured
- GitHub personal access token or GitHub App
- Blastauri GitHub Action or Docker image

## Step 1: Configure Permissions

### Using GITHUB_TOKEN (Automatic)

GitHub Actions provides `GITHUB_TOKEN` automatically. Ensure your workflow has these permissions:

```yaml
permissions:
  pull-requests: write
  contents: read
```

For WAF sync that creates PRs:

```yaml
permissions:
  pull-requests: write
  contents: write
```

### Using Personal Access Token

For enhanced access or cross-repository operations:

1. Navigate to GitHub > Settings > Developer settings > Personal access tokens
2. Generate new token (classic) with scopes:
   - `repo` - Full repository access
3. Add as repository secret:
   - Settings > Secrets and variables > Actions
   - New repository secret: `BLASTAURI_TOKEN`

## Step 2: Create Workflow

Create `.github/workflows/blastauri.yml`:

### Basic Dependabot Analysis

```yaml
name: Blastauri Analysis

on:
  pull_request:
    branches: [main]

permissions:
  pull-requests: write
  contents: read

jobs:
  analyze:
    runs-on: ubuntu-latest
    if: github.actor == 'dependabot[bot]'
    steps:
      - uses: actions/checkout@v4

      - uses: clay-good/blastauri@v1
        with:
          command: analyze
          post-comment: true
          apply-labels: true
          github-token: ${{ secrets.GITHUB_TOKEN }}
```

### Renovate Analysis on GitHub

```yaml
name: Blastauri Analysis

on:
  pull_request:
    branches: [main]

permissions:
  pull-requests: write
  contents: read

jobs:
  analyze:
    runs-on: ubuntu-latest
    if: github.actor == 'dependabot[bot]' || github.actor == 'renovate[bot]' || startsWith(github.head_ref, 'renovate/')
    steps:
      - uses: actions/checkout@v4

      - uses: clay-good/blastauri@v1
        with:
          command: analyze
          post-comment: true
          apply-labels: true
          severity-threshold: low
          github-token: ${{ secrets.GITHUB_TOKEN }}
```

### Full Workflow

```yaml
name: Blastauri

on:
  pull_request:
    branches: [main]
  push:
    branches: [main]
  schedule:
    - cron: '0 2 * * 1'  # Weekly Monday 2 AM

permissions:
  pull-requests: write
  contents: write
  security-events: write

jobs:
  # Analyze Dependabot/Renovate PRs
  analyze:
    runs-on: ubuntu-latest
    if: |
      github.event_name == 'pull_request' &&
      (github.actor == 'dependabot[bot]' ||
       github.actor == 'renovate[bot]' ||
       startsWith(github.head_ref, 'renovate/') ||
       startsWith(github.head_ref, 'dependabot/'))
    steps:
      - uses: actions/checkout@v4

      - uses: clay-good/blastauri@v1
        id: blastauri
        with:
          command: analyze
          post-comment: true
          apply-labels: true
          severity-threshold: medium
          github-token: ${{ secrets.GITHUB_TOKEN }}

      - name: Fail on critical breaking changes
        if: steps.blastauri.outputs.breaking-changes > 5
        run: |
          echo "Too many breaking changes detected"
          exit 1

  # Scan dependencies on main branch
  scan:
    runs-on: ubuntu-latest
    if: github.event_name == 'push'
    steps:
      - uses: actions/checkout@v4

      - uses: clay-good/blastauri@v1
        with:
          command: scan
          output-format: sarif
          github-token: ${{ secrets.GITHUB_TOKEN }}

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: blastauri-report.sarif

  # Weekly WAF sync
  waf-sync:
    runs-on: ubuntu-latest
    if: github.event_name == 'schedule'
    steps:
      - uses: actions/checkout@v4

      - uses: clay-good/blastauri@v1
        id: waf
        with:
          command: waf-sync
          waf-provider: aws
          waf-mode: log
          create-mr: true
          github-token: ${{ secrets.GITHUB_TOKEN }}

      - name: Report PR
        if: steps.waf.outputs.mr-url != ''
        run: echo "Created PR: ${{ steps.waf.outputs.mr-url }}"
```

## Step 3: Configure Blastauri

Create `.blastauri.yml` in your repository:

```yaml
version: 1
platform: github

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

github:
  api_url: https://api.github.com
```

## Action Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `command` | Command: analyze, scan, waf-sync | analyze |
| `path` | Repository path | . |
| `config` | Config file path | .blastauri.yml |
| `pr-number` | PR number (auto-detected) | - |
| `post-comment` | Post PR comment | true |
| `apply-labels` | Apply severity labels | true |
| `severity-threshold` | Minimum severity | low |
| `waf-provider` | WAF provider | aws |
| `waf-mode` | WAF rule mode | log |
| `waf-output-dir` | Terraform output | ./terraform/waf |
| `create-mr` | Create PR for WAF | false |
| `output-format` | Scan format | table |
| `github-token` | GitHub token | github.token |

## Action Outputs

| Output | Description |
|--------|-------------|
| `breaking-changes` | Number of breaking changes |
| `vulnerabilities` | Number of vulnerabilities |
| `waf-rules-created` | WAF rules created |
| `mr-url` | Created PR URL |

## Using Docker Directly

For custom workflows:

```yaml
jobs:
  analyze:
    runs-on: ubuntu-latest
    container:
      image: ghcr.io/clay-good/blastauri:latest
    steps:
      - uses: actions/checkout@v4

      - name: Run analysis
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          blastauri analyze \
            --repo "${{ github.repository }}" \
            --pr "${{ github.event.pull_request.number }}" \
            --comment \
            --label
```

## Dependabot Configuration

Ensure Dependabot is configured in `.github/dependabot.yml`:

```yaml
version: 2
updates:
  - package-ecosystem: npm
    directory: "/"
    schedule:
      interval: weekly
    open-pull-requests-limit: 10

  - package-ecosystem: pip
    directory: "/"
    schedule:
      interval: weekly
```

## Renovate Configuration

For Renovate on GitHub, configure `renovate.json`:

```json
{
  "$schema": "https://docs.renovatebot.com/renovate-schema.json",
  "extends": ["config:recommended"],
  "packageRules": [
    {
      "matchUpdateTypes": ["major"],
      "labels": ["major-update"]
    }
  ]
}
```

## Labels Created

Blastauri creates these labels on your repository:

| Label | Color | Description |
|-------|-------|-------------|
| `security:critical` | #FF0000 | Critical security vulnerability |
| `security:high` | #FF6600 | High severity issue |
| `security:medium` | #FFCC00 | Medium severity issue |
| `security:low` | #00CC00 | Low severity issue |
| `blastauri:breaking` | #FF0000 | Contains breaking changes |
| `blastauri:safe` | #00CC00 | Safe to merge |
| `blastauri:needs-review` | #FFCC00 | Requires manual review |
| `blastauri:waf-available` | #0066FF | WAF protection available |

## Security Scanning Integration

Upload scan results to GitHub Security:

```yaml
- uses: clay-good/blastauri@v1
  with:
    command: scan
    output-format: sarif

- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: blastauri-report.sarif
```

Results appear in Security > Code scanning alerts.

## GitHub Enterprise

For GitHub Enterprise Server:

```yaml
- uses: clay-good/blastauri@v1
  with:
    command: analyze
    github-token: ${{ secrets.GITHUB_TOKEN }}
  env:
    GITHUB_API_URL: https://github.example.com/api/v3
```

Or in `.blastauri.yml`:

```yaml
github:
  api_url: https://github.example.com/api/v3
```

## Conditional Analysis

Skip analysis for certain PRs:

```yaml
jobs:
  analyze:
    runs-on: ubuntu-latest
    if: |
      github.event_name == 'pull_request' &&
      !contains(github.event.pull_request.labels.*.name, 'skip-blastauri')
```

## Rate Limiting

For heavy usage, add an NVD API key:

1. Register at https://nvd.nist.gov/developers/request-an-api-key
2. Add as repository secret: `NVD_API_KEY`
3. Pass to action:

```yaml
- uses: clay-good/blastauri@v1
  with:
    command: analyze
    github-token: ${{ secrets.GITHUB_TOKEN }}
  env:
    NVD_API_KEY: ${{ secrets.NVD_API_KEY }}
```

## Next Steps

- [Configuration Reference](configuration.md)
- [WAF Rules Guide](waf-rules.md)
- [Troubleshooting](troubleshooting.md)

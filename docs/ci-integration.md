# CI/CD Integration

Blastauri integrates with GitLab CI and GitHub Actions to automatically analyze dependency upgrade MRs/PRs and manage WAF rules.

## GitLab CI

### Quick Start

Add Blastauri to your `.gitlab-ci.yml`:

```yaml
include:
  - remote: 'https://raw.githubusercontent.com/clay-good/blastauri/main/.gitlab/ci/blastauri.yml'

blastauri:
  extends: .blastauri-renovate
  variables:
    GITLAB_TOKEN: $CI_JOB_TOKEN
```

This configuration:
- Runs automatically on Renovate MRs (branches matching `renovate/*`)
- Posts analysis comments on the MR
- Applies severity labels

### Available Job Templates

#### `.blastauri-renovate`

Analyze Renovate merge requests:

```yaml
blastauri-analyze:
  extends: .blastauri-renovate
  variables:
    GITLAB_TOKEN: $CI_JOB_TOKEN
```

Trigger conditions:
- Merge request exists
- Source branch matches `renovate/*`

#### `.blastauri-waf`

Synchronize WAF rules:

```yaml
blastauri-waf:
  extends: .blastauri-waf
  variables:
    GITLAB_TOKEN: $CI_JOB_TOKEN
    WAF_PROVIDER: aws
```

Trigger conditions:
- Scheduled pipeline
- Manual trigger

#### `.blastauri-scan`

Scan dependencies and generate SARIF report:

```yaml
blastauri-scan:
  extends: .blastauri-scan
```

Produces:
- `blastauri-report.sarif` artifact
- GitLab SAST report integration

### Full Example

```yaml
include:
  - remote: 'https://raw.githubusercontent.com/clay-good/blastauri/main/.gitlab/ci/blastauri.yml'

stages:
  - test
  - deploy

# Analyze Renovate MRs
blastauri-analyze:
  extends: .blastauri-renovate
  stage: test
  variables:
    GITLAB_TOKEN: $CI_JOB_TOKEN

# Scan all dependencies
blastauri-scan:
  extends: .blastauri-scan
  stage: test
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH

# Sync WAF rules weekly
blastauri-waf-sync:
  extends: .blastauri-waf
  stage: deploy
  variables:
    GITLAB_TOKEN: $CI_JOB_TOKEN
    WAF_PROVIDER: aws
  rules:
    - if: $CI_PIPELINE_SOURCE == "schedule"
```

### Custom Configuration

Override the base template settings:

```yaml
blastauri-custom:
  extends: .blastauri
  stage: test
  script:
    - |
      blastauri analyze \
        --project "$CI_PROJECT_PATH" \
        --mr "$CI_MERGE_REQUEST_IID" \
        --severity high \
        --comment \
        --label
  rules:
    - if: $CI_MERGE_REQUEST_IID
```

### Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `GITLAB_TOKEN` | GitLab API token | Required |
| `WAF_PROVIDER` | WAF provider (aws, cloudflare) | aws |
| `BLASTAURI_LOG_LEVEL` | Log level | INFO |
| `NVD_API_KEY` | NVD API key for CVE lookups | Optional |

### Self-Hosted GitLab

For self-hosted GitLab instances:

```yaml
blastauri:
  extends: .blastauri-renovate
  variables:
    GITLAB_TOKEN: $CI_JOB_TOKEN
    GITLAB_URL: https://gitlab.example.com
```

Or configure in `.blastauri.yml`:

```yaml
gitlab:
  url: https://gitlab.example.com
```

## GitHub Actions

### Quick Start

Create `.github/workflows/blastauri.yml`:

```yaml
name: Blastauri Analysis

on:
  pull_request:
    branches: [main]

jobs:
  analyze:
    runs-on: ubuntu-latest
    if: github.actor == 'dependabot[bot]' || startsWith(github.head_ref, 'renovate/')
    steps:
      - uses: actions/checkout@v4
      - uses: clay-good/blastauri@v1
        with:
          command: analyze
          github-token: ${{ secrets.GITHUB_TOKEN }}
```

### Action Inputs

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
| `waf-output-dir` | Terraform output dir | ./terraform/waf |
| `create-mr` | Create MR for WAF changes | false |
| `output-format` | Scan output format | table |
| `github-token` | GitHub token | github.token |

### Action Outputs

| Output | Description |
|--------|-------------|
| `breaking-changes` | Number of breaking changes detected |
| `vulnerabilities` | Number of vulnerabilities detected |
| `waf-rules-created` | Number of WAF rules created |
| `mr-url` | URL of created MR/PR |

### Analyze Dependabot PRs

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
        id: blastauri
        with:
          command: analyze
          post-comment: true
          apply-labels: true
          severity-threshold: medium
          github-token: ${{ secrets.GITHUB_TOKEN }}

      - name: Check for breaking changes
        if: steps.blastauri.outputs.breaking-changes > 0
        run: |
          echo "Breaking changes detected: ${{ steps.blastauri.outputs.breaking-changes }}"
          exit 1
```

### Scan Dependencies

```yaml
name: Dependency Scan

on:
  push:
    branches: [main]
  schedule:
    - cron: '0 0 * * 1'  # Weekly on Monday

jobs:
  scan:
    runs-on: ubuntu-latest
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
```

### WAF Sync on Schedule

```yaml
name: WAF Sync

on:
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM
  workflow_dispatch:

permissions:
  pull-requests: write
  contents: write

jobs:
  sync:
    runs-on: ubuntu-latest
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

      - name: Report PR URL
        if: steps.waf.outputs.mr-url != ''
        run: echo "Created PR: ${{ steps.waf.outputs.mr-url }}"
```

### Full Workflow Example

```yaml
name: Blastauri

on:
  pull_request:
    branches: [main]
  push:
    branches: [main]
  schedule:
    - cron: '0 2 * * 1'

permissions:
  pull-requests: write
  contents: write
  security-events: write

jobs:
  # Analyze Dependabot/Renovate PRs
  analyze:
    runs-on: ubuntu-latest
    if: github.event_name == 'pull_request' && (github.actor == 'dependabot[bot]' || startsWith(github.head_ref, 'renovate/'))
    steps:
      - uses: actions/checkout@v4
      - uses: clay-good/blastauri@v1
        with:
          command: analyze
          post-comment: true
          apply-labels: true
          github-token: ${{ secrets.GITHUB_TOKEN }}

  # Scan on main branch pushes
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
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: blastauri-report.sarif

  # Weekly WAF sync
  waf-sync:
    runs-on: ubuntu-latest
    if: github.event_name == 'schedule'
    steps:
      - uses: actions/checkout@v4
      - uses: clay-good/blastauri@v1
        with:
          command: waf-sync
          waf-provider: aws
          create-mr: true
          github-token: ${{ secrets.GITHUB_TOKEN }}
```

## Docker Usage

Run Blastauri directly with Docker:

```bash
# Analyze a GitLab MR
docker run --rm \
  -e GITLAB_TOKEN="$GITLAB_TOKEN" \
  ghcr.io/clay-good/blastauri:latest \
  analyze --project mygroup/myproject --mr 123

# Scan local directory
docker run --rm \
  -v "$(pwd):/workspace" \
  ghcr.io/clay-good/blastauri:latest \
  scan /workspace

# Generate WAF rules
docker run --rm \
  -v "$(pwd):/workspace" \
  ghcr.io/clay-good/blastauri:latest \
  waf generate /workspace --output-dir /workspace/terraform/waf
```

### Docker in CI

GitLab CI:

```yaml
blastauri:
  image: ghcr.io/clay-good/blastauri:latest
  script:
    - blastauri analyze --project "$CI_PROJECT_PATH" --mr "$CI_MERGE_REQUEST_IID"
  rules:
    - if: $CI_MERGE_REQUEST_IID
```

GitHub Actions:

```yaml
jobs:
  analyze:
    runs-on: ubuntu-latest
    container:
      image: ghcr.io/clay-good/blastauri:latest
    steps:
      - uses: actions/checkout@v4
      - run: blastauri analyze --repo "${{ github.repository }}" --pr "${{ github.event.pull_request.number }}"
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

## Troubleshooting

### Common Issues

**Token permissions**: Ensure your token has permissions to:
- Read repository contents
- Post comments on MRs/PRs
- Apply labels to MRs/PRs
- Create branches (for WAF sync)

**Rate limiting**: For heavy usage, provide an NVD API key:

```yaml
variables:
  NVD_API_KEY: $NVD_API_KEY
```

**Self-signed certificates**: For self-hosted GitLab with custom CA:

```yaml
variables:
  GIT_SSL_NO_VERIFY: "true"
  REQUESTS_CA_BUNDLE: /path/to/ca-bundle.crt
```

### Debug Mode

Enable verbose logging:

```yaml
variables:
  BLASTAURI_LOG_LEVEL: DEBUG
```

Or via command line:

```bash
blastauri --verbose analyze ...
```

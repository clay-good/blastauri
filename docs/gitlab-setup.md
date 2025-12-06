# GitLab Setup Guide

This guide explains how to set up Blastauri for GitLab with Renovate.

## Prerequisites

- GitLab project with Renovate configured
- GitLab personal access token or CI job token
- Blastauri installed or Docker image available

## Step 1: Create GitLab Token

### Option A: CI Job Token (Recommended)

GitLab CI provides `CI_JOB_TOKEN` automatically in pipeline jobs. This token has limited permissions scoped to the current project.

For cross-project access or enhanced permissions, use a personal access token instead.

### Option B: Personal Access Token

1. Navigate to GitLab > User Settings > Access Tokens
2. Create a new token with these scopes:
   - `api` - Full API access
3. Set an appropriate expiration date
4. Copy the token value

## Step 2: Configure CI Variables

### Using CI Job Token

No additional configuration needed. The `CI_JOB_TOKEN` is available automatically.

### Using Personal Access Token

1. Navigate to your project > Settings > CI/CD > Variables
2. Add a new variable:
   - Key: `GITLAB_TOKEN`
   - Value: Your personal access token
   - Type: Variable
   - Protected: Yes (recommended)
   - Masked: Yes (required)

### Optional: NVD API Key

For higher rate limits on CVE queries:

1. Register at https://nvd.nist.gov/developers/request-an-api-key
2. Add CI variable:
   - Key: `NVD_API_KEY`
   - Value: Your API key
   - Masked: Yes

## Step 3: Configure GitLab CI

Add Blastauri to your `.gitlab-ci.yml`:

### Basic Configuration

```yaml
include:
  - remote: 'https://raw.githubusercontent.com/clay-good/blastauri/main/.gitlab/ci/blastauri.yml'

blastauri:
  extends: .blastauri-renovate
  variables:
    GITLAB_TOKEN: $CI_JOB_TOKEN
```

### Full Configuration

```yaml
include:
  - remote: 'https://raw.githubusercontent.com/clay-good/blastauri/main/.gitlab/ci/blastauri.yml'

stages:
  - test
  - deploy

# Analyze Renovate MRs automatically
blastauri-analyze:
  extends: .blastauri-renovate
  stage: test
  variables:
    GITLAB_TOKEN: $CI_JOB_TOKEN
    BLASTAURI_LOG_LEVEL: INFO

# Scan dependencies on main branch
blastauri-scan:
  extends: .blastauri-scan
  stage: test
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH

# Weekly WAF synchronization
blastauri-waf-sync:
  extends: .blastauri-waf
  stage: deploy
  variables:
    GITLAB_TOKEN: $GITLAB_TOKEN  # Needs PAT for MR creation
    WAF_PROVIDER: aws
  rules:
    - if: $CI_PIPELINE_SOURCE == "schedule"
```

### Custom Configuration

For custom analysis settings:

```yaml
blastauri-custom:
  image: ghcr.io/clay-good/blastauri:latest
  stage: test
  variables:
    GITLAB_TOKEN: $CI_JOB_TOKEN
  script:
    - |
      blastauri analyze \
        --project "$CI_PROJECT_PATH" \
        --mr "$CI_MERGE_REQUEST_IID" \
        --severity medium \
        --comment \
        --label
  rules:
    - if: $CI_MERGE_REQUEST_IID && $CI_MERGE_REQUEST_SOURCE_BRANCH_NAME =~ /^renovate\//
  allow_failure: true
```

## Step 4: Configure Blastauri

Create `.blastauri.yml` in your repository root:

```yaml
version: 1
platform: gitlab

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
```

## Step 5: Verify Setup

### Test MR Analysis

1. Create or wait for a Renovate MR
2. Check the pipeline runs on the MR
3. Verify the analysis comment appears
4. Check labels are applied

### Test Manually

```bash
# Set token
export GITLAB_TOKEN="your-token"

# Analyze an existing Renovate MR
blastauri analyze --project mygroup/myproject --mr 123

# Scan local repository
blastauri scan .
```

## Pipeline Triggers

### Renovate MR Trigger

The `.blastauri-renovate` job uses this rule:

```yaml
rules:
  - if: $CI_MERGE_REQUEST_IID && $CI_MERGE_REQUEST_SOURCE_BRANCH_NAME =~ /^renovate\//
    when: always
  - when: never
```

This triggers on:
- Merge request pipelines
- Source branch starts with `renovate/`

### Scheduled WAF Sync

Configure a pipeline schedule for WAF synchronization:

1. Navigate to project > CI/CD > Schedules
2. Create new schedule:
   - Description: "Weekly WAF Sync"
   - Interval: Custom (`0 2 * * 1` for Monday 2 AM)
   - Target branch: main
3. Add variable `WAF_PROVIDER` = `aws` or `cloudflare`

## Self-Hosted GitLab

For self-hosted GitLab instances:

### Configure Base URL

```yaml
blastauri:
  extends: .blastauri-renovate
  variables:
    GITLAB_TOKEN: $CI_JOB_TOKEN
    GITLAB_URL: https://gitlab.example.com
```

Or in `.blastauri.yml`:

```yaml
gitlab:
  url: https://gitlab.example.com
```

### SSL Certificate Issues

For self-signed certificates:

```yaml
blastauri:
  extends: .blastauri-renovate
  variables:
    GITLAB_TOKEN: $CI_JOB_TOKEN
    GIT_SSL_NO_VERIFY: "true"
    REQUESTS_CA_BUNDLE: /path/to/ca-bundle.crt
```

## Labels Created

Blastauri creates and manages these labels:

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

## Analysis Comment

Blastauri posts a comment on each analyzed MR containing:

- Overall risk score (0-100)
- Severity classification (Critical/High/Medium/Low)
- Breaking changes with file locations
- CVEs fixed by the upgrade
- Suggested fixes
- Recommendations

The comment includes the marker `<!-- blastauri-analysis -->` for identification. Subsequent analyses update the existing comment rather than creating new ones.

## Permissions Required

### CI Job Token

- Read repository
- Read/write merge requests
- Read/write labels

### Personal Access Token

- `api` scope for full access

For WAF sync with MR creation, a personal access token is required as CI job tokens cannot create merge requests in some configurations.

## Next Steps

- [Configuration Reference](configuration.md)
- [WAF Rules Guide](waf-rules.md)
- [Troubleshooting](troubleshooting.md)

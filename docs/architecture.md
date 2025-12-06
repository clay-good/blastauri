# Architecture

This document describes the system architecture of Blastauri.

## System Overview

Blastauri operates in two modes:

1. **Renovate MR Analysis** - Triggered by merge request pipelines
2. **WAF Rule Management** - Triggered by schedule or manual invocation

```mermaid
graph TB
    subgraph "Mode 1: MR Analysis"
        R[Renovate creates MR] --> T[GitLab CI triggers blastauri]
        T --> P[Parse MR diff]
        P --> Q[Query CVE databases]
        Q --> S[Static analysis]
        S --> I[Impact report]
        I --> L[Apply labels]
        L --> C[Post comment]
    end

    subgraph "Mode 2: WAF Management"
        SCH[Scheduled pipeline] --> SCAN[Scan lockfiles]
        SCAN --> CVE[Query CVE databases]
        CVE --> FILTER[Filter WAF-mitigatable]
        FILTER --> CHECK[Check existing rules]
        CHECK --> GEN[Generate Terraform]
        GEN --> MR[Create MR]
    end
```

## Component Architecture

```mermaid
graph TD
    CLI[cli.py] --> CORE[core/]
    CLI --> CONFIG[config.py]

    CORE --> SCANNERS[scanners/]
    CORE --> CVE[cve/]
    CORE --> ANALYSIS[analysis/]
    CORE --> WAF[waf/]
    CORE --> GIT[git/]

    subgraph "scanners/"
        S_BASE[base.py]
        S_NPM[npm.py]
        S_PIP[pip.py]
        S_GO[go.py]
        S_RUBY[ruby.py]
        S_MAVEN[maven.py]
        S_CARGO[cargo.py]
        S_COMPOSER[composer.py]
        S_DETECTOR[detector.py]
    end

    subgraph "cve/"
        C_NVD[nvd.py]
        C_GITHUB[github_advisories.py]
        C_OSV[osv.py]
        C_GITLAB[gitlab_advisories.py]
        C_CACHE[cache.py]
        C_AGG[aggregator.py]
        C_WAF[waf_patterns.py]
    end

    subgraph "analysis/"
        A_CHANGELOG[changelog_parser.py]
        A_STATIC[static_analyzer.py]
        A_USAGE[usage_finder.py]
        A_IMPACT[impact_calculator.py]
        A_FIX[fix_generator.py]
        A_AI[ai_reviewer.py]
    end

    subgraph "waf/"
        W_GEN[generator.py]
        W_LIFE[lifecycle.py]
        W_AWS[providers/aws.py]
        W_CF[providers/cloudflare.py]
        W_TEMPLATES[rule_templates.py]
    end

    subgraph "git/"
        G_GITLAB[gitlab_client.py]
        G_GITHUB[github_client.py]
        G_RENOVATE[renovate_parser.py]
        G_DEPENDABOT[dependabot_parser.py]
        G_COMMENT[comment_generator.py]
        G_LABEL[label_manager.py]
        G_MR[mr_creator.py]
    end
```

## Data Flow

### Renovate MR Analysis Flow

```mermaid
sequenceDiagram
    participant R as Renovate
    participant G as GitLab CI
    participant B as Blastauri
    participant CVE as CVE Sources
    participant REPO as Repository

    R->>G: Create MR (renovate/lodash-4.x)
    G->>B: Trigger pipeline
    B->>G: Fetch MR details
    B->>G: Get lockfile diff
    B->>B: Parse dependency updates
    B->>CVE: Query vulnerabilities
    CVE-->>B: Return CVEs
    B->>REPO: Scan codebase
    B->>B: Find import/usage locations
    B->>B: Cross-reference breaking changes
    B->>B: Calculate risk score
    B->>G: Post analysis comment
    B->>G: Apply severity labels
```

### WAF Sync Flow

```mermaid
sequenceDiagram
    participant S as Scheduler
    participant B as Blastauri
    participant CVE as CVE Sources
    participant REPO as Repository
    participant G as GitLab

    S->>B: Trigger sync
    B->>REPO: Load WAF state
    B->>REPO: Scan lockfiles
    B->>CVE: Query vulnerabilities
    CVE-->>B: Return CVEs
    B->>B: Filter WAF-mitigatable
    B->>B: Compare with existing rules
    B->>B: Identify new/obsolete rules
    B->>B: Generate Terraform
    B->>G: Create branch
    B->>G: Commit Terraform files
    B->>G: Create MR
```

## Core Models

```mermaid
classDiagram
    class Dependency {
        +str name
        +str version
        +Ecosystem ecosystem
        +str location
        +bool is_dev
        +bool is_direct
        +str parent
    }

    class CVE {
        +str id
        +str description
        +Severity severity
        +float cvss_score
        +list affected_packages
        +bool is_waf_mitigatable
        +str waf_pattern_id
    }

    class BreakingChange {
        +BreakingChangeType change_type
        +str description
        +str old_api
        +str new_api
        +str migration_guide
    }

    class UsageLocation {
        +str file_path
        +int line_number
        +int column
        +str code_snippet
        +str usage_type
        +str symbol
    }

    class UpgradeImpact {
        +str dependency_name
        +Ecosystem ecosystem
        +str from_version
        +str to_version
        +bool is_major_upgrade
        +list breaking_changes
        +list impacted_locations
        +list cves_fixed
        +int risk_score
        +Severity severity
    }

    class AnalysisReport {
        +str merge_request_id
        +str repository
        +list upgrades
        +int overall_risk_score
        +Severity overall_severity
        +str summary
        +list recommendations
    }

    UpgradeImpact --> BreakingChange
    UpgradeImpact --> UsageLocation
    UpgradeImpact --> CVE
    AnalysisReport --> UpgradeImpact
```

## Data Storage

Blastauri is stateless by design. Only two storage locations:

| Storage | Location | Purpose | TTL |
|---------|----------|---------|-----|
| CVE Cache | ~/.cache/blastauri/cve.db | SQLite cache for CVE queries | 24 hours |
| WAF State | .blastauri/waf-state.json | Track active WAF rules | Committed to repo |

### CVE Cache Schema

```sql
CREATE TABLE cve_cache (
    cve_id TEXT PRIMARY KEY,
    data TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL
);

CREATE TABLE package_queries (
    query_key TEXT PRIMARY KEY,
    cve_ids TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL
);
```

### WAF State Schema

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

## Security Architecture

### Input Validation

All external input is validated:

- **Repository URLs**: No file:// or other dangerous schemes
- **MR/PR IDs**: Positive integers only
- **CVE IDs**: Pattern `CVE-\d{4}-\d{4,}`
- **File paths**: Sanitized for directory traversal
- **Dependency names**: Ecosystem-specific patterns

### Authentication

```mermaid
graph LR
    ENV[Environment Variables] --> BL[Blastauri]

    subgraph "Tokens"
        GL[GITLAB_TOKEN]
        GH[GITHUB_TOKEN]
        NVD[NVD_API_KEY]
    end

    GL --> BL
    GH --> BL
    NVD --> BL

    BL --> API1[GitLab API]
    BL --> API2[GitHub API]
    BL --> API3[NVD API]
```

### Network Security

- HTTPS exclusively for all requests
- SSL certificate verification enabled
- 30-second timeout on all requests
- Retry with exponential backoff (1/2/4 seconds)
- Rate limiting respected (NVD: 5 req/30s, 50 with API key)

### Code Execution Safety

Blastauri MUST NOT:

- Execute code from scanned repositories
- Use eval(), exec(), or dynamic execution
- Run shell commands with user input
- Import code from scanned dependencies

Static analysis is performed via AST parsing only.

## Risk Score Calculation

```mermaid
graph TD
    START[Calculate Risk Score] --> LOC[Impacted Locations]
    START --> BC[Breaking Changes]
    START --> MAJ[Major Version]
    START --> CVE[CVEs Fixed]

    LOC --> |0-30 points| SCORE
    BC --> |0-30 points| SCORE
    MAJ --> |0-20 points| SCORE
    CVE --> |-10 points| SCORE

    SCORE[Total Score] --> SEV{Severity}

    SEV --> |80-100| CRIT[CRITICAL]
    SEV --> |60-79| HIGH[HIGH]
    SEV --> |40-59| MED[MEDIUM]
    SEV --> |0-39| LOW[LOW]
```

## WAF Rule Lifecycle

```mermaid
stateDiagram-v2
    [*] --> Pending: CVE detected
    Pending --> LogMode: Terraform applied
    LogMode --> BlockMode: Manual promotion
    LogMode --> Obsolete: Dependency patched
    BlockMode --> Obsolete: Dependency patched
    Obsolete --> [*]: Rule removed
```

## Deployment Architecture

```mermaid
graph TB
    subgraph "GitLab CI"
        RUNNER[GitLab Runner]
        RUNNER --> DOCKER[Docker: blastauri]
    end

    subgraph "GitHub Actions"
        GHA[GitHub Actions]
        GHA --> ACTION[Action: blastauri]
    end

    subgraph "Local"
        DEV[Developer Machine]
        DEV --> PIP[pip install blastauri]
    end

    DOCKER --> GHCR[ghcr.io/clay-good/blastauri]
    ACTION --> GHCR
```

## Supported Ecosystems

| Ecosystem | Lockfiles | Parser |
|-----------|-----------|--------|
| npm | package-lock.json, yarn.lock, pnpm-lock.yaml | JSON/YAML |
| Python | requirements.txt, Pipfile.lock, poetry.lock | Text/JSON/TOML |
| Go | go.mod, go.sum | Text |
| Ruby | Gemfile.lock | Text |
| Maven | pom.xml | XML |
| Cargo | Cargo.lock | TOML |
| Composer | composer.lock | JSON |

## CVE Sources

| Source | API | Rate Limit |
|--------|-----|------------|
| NVD | REST API 2.0 | 5/30s (50 with key) |
| GitHub Advisories | GraphQL | Token-based |
| OSV | REST | Unlimited |
| GitLab Advisories | REST | Token-based |

# Blastauri

**Know what breaks before you merge.**

Blastauri analyzes Renovate and Dependabot merge requests to identify breaking changes, prioritize security updates, and help you triage the flood of dependency upgrade MRs.

> **Read-Only by Design**: Blastauri is an advisory tool. It analyzes and recommends - it never automatically modifies your code, merges MRs, or makes changes without human review. [See Safety Guarantees](#safety-guarantees-read-only-by-design).

## The Problem

Your team enabled Renovate. Now you have 47 open merge requests.

- Which ones are safe to merge?
- Which will break production?
- Which fix critical CVEs and need priority?
- Which can wait?

Traditional tools say "update available" or "vulnerability found." They don't tell you that upgrading lodash will break 12 files, or that the express update fixes a critical CVE you should prioritize.

**Result:** Teams either merge blindly (and break things) or ignore updates (and accumulate security debt).

## The Solution

Blastauri runs in your CI pipeline on every Renovate/Dependabot MR and tells you:

| Question | Answer |
|----------|--------|
| Will this break my code? | Detects breaking changes from changelogs and version analysis |
| Where exactly? | File paths, line numbers, code snippets |
| How risky? | Risk score 0-100 with severity labels |
| Does it fix CVEs? | Lists CVEs fixed with severity ratings |
| Is this CVE exploitable in MY code? | **Vulnerability reachability analysis** shows if your code actually calls vulnerable functions |
| Can I protect myself now? | Generates WAF rules for critical CVEs |

## How It Works

```
Renovate creates MR
        |
        v
Blastauri runs in CI
        |
        +---> Parses lockfile diff
        |
        +---> Detects breaking changes (6 strategies):
        |       - Semver version analysis
        |       - Known breaking changes database
        |       - Package registry metadata (deprecation, peer deps, engines)
        |       - API diff (downloads & compares exports)
        |       - Heuristics (size, file count, export count changes)
        |       - Changelog parsing (fallback)
        |
        +---> Checks repository status (archived, unmaintained)
        |
        +---> Finds usage locations in your code (AST analysis)
        |
        +---> Queries CVE databases (NVD, GitHub, OSV)
        |
        +---> Checks vulnerability reachability (is YOUR code affected?)
        |
        +---> Calculates risk score
        |
        v
Posts comment + applies labels
```

### 100% Deterministic Core Analysis

**All core functionality runs without LLM calls.** You can trust the analysis because it's based on deterministic logic:

| Feature | How It Works |
|---------|--------------|
| Breaking change detection | **Multi-strategy approach** (see below) |
| Code usage detection | AST-based static analysis. Finds imports, function calls, and property access matching affected APIs. |
| **Vulnerability reachability** | Builds call graph from your code, traces paths from entry points to vulnerable function calls. Identifies which CVEs are actually exploitable in YOUR codebase. |
| Risk scoring | Weighted algorithm: `locations(0-30) + breaking_changes(0-30) + major_upgrade(0-20) - cves_fixed(10 each)` |
| CVE lookup | Queries NVD, GitHub Advisories, OSV, and GitLab databases via their public APIs. |
| WAF rule generation | Template-based Terraform generation with pattern matching for known CVE signatures. |
| Label application | Rules-based: severity thresholds map directly to label names. |

No API calls to OpenAI, Anthropic, or any LLM service are made during core analysis.

### Breaking Change Detection (6-Strategy Approach)

Blastauri uses **six complementary strategies** to detect breaking changes, significantly reducing reliance on changelog quality:

| Priority | Strategy | Reliability | Description |
|----------|----------|-------------|-------------|
| 1 | **Semver Analysis** | High | Major version bumps flagged as breaking. 0.x to 1.x transitions treated as first stable release. |
| 2 | **Known Breaking Changes Database** | High | Curated database for popular packages (lodash, express, react, pydantic, django, axios, etc.) with exact version ranges and migration guides. |
| 3 | **Package Metadata Analysis** | High | Detects deprecation warnings, peer dependency changes, engine requirement changes (Node/Python version), removed TypeScript types, and exports field changes from npm/PyPI registries. |
| 4 | **API Diff Analysis** | High | Downloads both package versions and compares actual exports. Parses TypeScript `.d.ts` files (with full type signatures) and Python AST (with parameter and return types). |
| 5 | **Heuristic Analysis** | Medium | Detects package size reduction, file count reduction, export count reduction, dependency removals, and version pattern indicators (e.g., `-next`, `-rewrite` suffixes). |
| 6 | **Changelog Parsing** | Variable | Parses GitHub Releases, CHANGELOG.md, and registry metadata for breaking change keywords. Fallback when other methods don't provide data. |

**Additional Signals:**
- **Repository Status**: Checks if GitHub repository is archived, unmaintained (no commits in 1+ year), or has a large open issues backlog
- **@types Fallback**: For npm packages without embedded types, checks for `@types/*` package availability

**Result:** Even packages with poor or missing changelogs get accurate breaking change detection through API comparison, registry metadata, heuristics, and the curated database.

### Optional AI Review (Bring Your Own Keys)

For teams that want enhanced analysis, Blastauri supports **optional** AI-assisted review:

```yaml
# .blastauri.yml
analysis:
  ai_provider: claude  # or "augment" or "none" (default)
```

**When enabled:**
- Requires the `claude` or `augment` CLI tool installed locally
- Uses **your own API keys** configured in those tools
- Blastauri does NOT store, transmit, or require any API keys
- AI review is additive - core analysis always runs first

**What AI adds (when enabled):**
- Natural language summary of upgrade impact
- Pattern recognition for risky upgrade combinations
- Suggested code fixes for breaking changes

**Default behavior:** AI is disabled (`ai_provider: none`). Core analysis provides everything you need.

**Example comment on MR:**

```
## Blastauri Dependency Analysis

### Status: HIGH RISK - Review Recommended

| Metric | Value |
|--------|-------|
| Risk Score | 65/100 |
| Severity | HIGH |
| Breaking Changes | 3 |
| CVEs Fixed | 2 |

### Package Upgrades

#### ! lodash `4.17.15` -> `5.0.0` (MAJOR)
- **Risk Score:** 65/100 (high)
- **Breaking Changes:** 3
  - REMOVED_FUNCTION: _.pluck removed, use _.map
  - CHANGED_SIGNATURE: _.merge now handles arrays differently
- **Impacted Locations:** 12 in 4 file(s)
- **Security:** 1 CVE(s) fixed (1 high)

### Recommendations
- Review all breaking changes before merging
- Update 12 code location(s) affected by breaking changes
- Run full test suite to verify no regressions
```

## Quick Start

### GitLab + Renovate (2 minutes)

1. Add to `.gitlab-ci.yml`:

```yaml
include:
  - remote: 'https://raw.githubusercontent.com/clay-good/blastauri/main/.gitlab/ci/blastauri.yml'

blastauri:
  extends: .blastauri-renovate
  variables:
    GITLAB_TOKEN: $CI_JOB_TOKEN
```

2. That's it. Blastauri will automatically analyze MRs from branches matching `renovate/*`.

### GitHub + Dependabot (2 minutes)

1. Create `.github/workflows/blastauri.yml`:

```yaml
name: Blastauri
on:
  pull_request:
    branches: [main]

permissions:
  pull-requests: write
  contents: read

jobs:
  analyze:
    runs-on: ubuntu-latest
    if: github.actor == 'dependabot[bot]' || startsWith(github.head_ref, 'renovate/')
    steps:
      - uses: actions/checkout@v4
      - uses: clay-good/blastauri@v1
        with:
          github-token: ${{ secrets.GITHUB_TOKEN }}
```

2. That's it. Blastauri will analyze Dependabot and Renovate PRs automatically.

## What You Get

### On Every Dependency MR/PR:

- **Risk score** (0-100) based on breaking changes, usage impact, and version jump
- **Severity label** applied to MR: `security:critical`, `security:high`, `blastauri:safe`, `blastauri:breaking`
- **Detailed comment** listing breaking changes, affected files, and CVEs fixed
- **Recommendations** for how to proceed

### Labels Applied:

| Label | Meaning |
|-------|---------|
| `blastauri:safe` | Low risk, no breaking changes detected |
| `blastauri:breaking` | Breaking changes detected, review needed |
| `blastauri:needs-review` | Medium risk, manual review suggested |
| `security:critical` | Fixes critical CVE, prioritize |
| `security:high` | Fixes high severity CVE |
| `blastauri:waf-available` | WAF rules can mitigate the CVE |

## Safety Guarantees (Read-Only by Design)

Blastauri is designed to **help developers, not replace them**. It addresses dependency upgrade fatigue by surfacing relevant information so YOU can make informed decisions.

### What Blastauri Does

| Action | Description |
|--------|-------------|
| **Analyzes** | Reads MRs, lockfiles, and package registries |
| **Reports** | Posts comments with analysis results |
| **Labels** | Adds metadata labels for triage |
| **Generates** | Creates WAF Terraform files locally (your machine) |
| **Proposes** | Creates separate MRs for WAF changes (requires your approval) |

### What Blastauri NEVER Does

| Never | Why |
|-------|-----|
| Modifies source code | Your code, your control |
| Auto-merges MRs/PRs | Humans approve all changes |
| Commits to main/master | Protected branches stay protected |
| Deploys WAF rules | You run `terraform apply` |
| Makes irreversible changes | Comments/labels are easily removed |

### All Actions Are Reversible

- Comments can be edited or deleted
- Labels can be removed
- WAF MRs can be closed without merging
- Local Terraform files can be deleted
- No state is modified without explicit `terraform apply`

## WAF Protection (Environment-Confirmed Threat Intelligence)

**Threat intelligence is only useful if it's confirmed in YOUR environment.**

Traditional vulnerability scanners tell you "CVE-2021-44228 exists." But do you actually USE the vulnerable code path? Is the CVE exploitable in your setup?

Blastauri confirms:
1. **The vulnerability exists** in a package you depend on
2. **Your code uses** the affected functionality (via static analysis)
3. **A WAF rule can mitigate** the attack vector
4. **Here's the rule** ready for your review

```bash
# Generate WAF rules for CVEs confirmed in YOUR environment
blastauri waf generate ./my-project --provider aws

# Creates a separate MR for human review (never auto-merges)
blastauri waf sync --project mygroup/myproject --create-mr
```

### How WAF Lifecycle Works

```
CVE detected in your dependencies
        |
        v
Blastauri checks if your code uses affected APIs
        |
        v
If exploitable: Generates WAF rule (Terraform)
        |
        v
Creates MR with WAF changes (YOU review and merge)
        |
        v
YOU run terraform apply (Blastauri never deploys)
        |
        v
Rule starts in LOG mode (monitor, don't block)
        |
        v
After 14 days with no false positives:
Blastauri proposes promotion to BLOCK mode (YOU approve)
        |
        v
When you upgrade the package:
Blastauri proposes removing the now-obsolete rule (YOU approve)
```

### Supported Providers

- AWS WAFv2 (Terraform)
- Cloudflare WAF (Terraform)

### Built-in Protection Templates

- Log4Shell (CVE-2021-44228)
- Spring4Shell (CVE-2022-22965)
- Text4Shell (CVE-2022-42889)
- Prototype Pollution
- SQL Injection, XSS, SSRF, XXE
- And more...

## Vulnerability Reachability Analysis

**Not all vulnerabilities are created equal.** A CVE in a dependency you never actually call is low priority.

Blastauri's reachability analysis goes beyond simple "dependency contains CVE" detection:

```
Your dependency has CVE-2017-18342 (PyYAML unsafe load)
                    |
                    v
Does your code call yaml.load()? ─────────────> NO: SAFE TO IGNORE
                    |                              (unreachable)
                    v YES
Is it called from an entry point? ────────────> Call trace shows path
                    |
                    v
REACHABLE: This CVE affects YOUR code
```

### How It Works

1. **Builds Call Graph**: Parses your source code using tree-sitter AST analysis
2. **Maps Imports**: Resolves import statements to track which modules are used
3. **Identifies Vulnerable Symbols**: Matches CVEs to specific function signatures
4. **Traces Execution Paths**: BFS traversal from entry points to vulnerable calls

### Reachability Statuses

| Status | Meaning | Action |
|--------|---------|--------|
| `REACHABLE` | Confirmed path from entry point to vulnerable function | **Prioritize fix** |
| `POTENTIALLY_REACHABLE` | Package imported but call path unclear | Review manually |
| `UNREACHABLE` | Vulnerable function never called | Safe to deprioritize |
| `UNKNOWN` | No function-level data for this CVE | Treat as potentially vulnerable |

### Usage

```bash
# Scan with reachability analysis enabled
blastauri scan ./my-project --reachability

# Hide unreachable vulnerabilities (focus on real risks)
blastauri scan ./my-project --reachability --hide-unreachable

# Check reachability for specific packages
blastauri check-reachability ./my-project --package pyyaml

# Check reachability for specific CVE
blastauri check-reachability ./my-project --cve CVE-2017-18342
```

### Example Output

```
Reachability Analysis Results
┏━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ CVE              ┃ Package  ┃ Status     ┃ Trace                                              ┃
┡━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ CVE-2017-18342   │ pyyaml   │ REACHABLE  │ main() -> parse_config() -> yaml.load()           │
│ CVE-2021-23337   │ lodash   │ UNREACHABLE│ -                                                  │
│ CVE-2021-3749    │ axios    │ REACHABLE  │ app() -> fetchData() -> axios.get()               │
└──────────────────┴──────────┴────────────┴────────────────────────────────────────────────────┘

Summary: 10 CVEs found, 2 REACHABLE, 8 safe to ignore
```

### Supported Languages

| Language | Import Resolution | Call Graph | Status |
|----------|------------------|------------|--------|
| Python | Full (import, from X import Y, aliases) | Full | Production |
| JavaScript/TypeScript | Full (ES6 imports, CommonJS require) | Full | Production |
| Go | Basic | Basic | Beta |
| Ruby | Basic | - | Experimental |

## Installation

### pip (recommended)

```bash
pip install blastauri
```

### Docker

```bash
docker pull ghcr.io/clay-good/blastauri:latest
```

### From source

```bash
git clone https://github.com/clay-good/blastauri.git
cd blastauri
pip install -e .
```

## CLI Reference

```bash
# Analyze a GitLab MR
blastauri analyze --project mygroup/myproject --mr 123

# Analyze a GitHub PR
blastauri analyze --repo owner/repo --pr 456

# Scan local directory for vulnerabilities
blastauri scan ./my-project

# Scan with reachability analysis
blastauri scan ./my-project --reachability

# Scan and hide unreachable vulnerabilities (show only real risks)
blastauri scan ./my-project --reachability --hide-unreachable

# Scan with JSON output
blastauri scan ./my-project --format json --output report.json

# Scan with severity filter
blastauri scan ./my-project --severity high

# Check vulnerability reachability
blastauri check-reachability ./my-project

# Check reachability for specific CVE
blastauri check-reachability ./my-project --cve CVE-2017-18342

# Check reachability for specific package
blastauri check-reachability ./my-project --package pyyaml

# Generate WAF rules for detected CVEs
blastauri waf generate ./my-project --provider aws --output ./terraform/waf

# Generate WAF rules for specific CVEs
blastauri waf generate --cves CVE-2021-44228,CVE-2022-22965 --output ./terraform/waf

# Generate OWASP Top 10 protection rules
blastauri waf generate --owasp --output ./terraform/waf

# Check WAF status
blastauri waf status

# List available WAF templates
blastauri waf templates

# Sync WAF rules with current state
blastauri waf sync --project mygroup/myproject

# Initialize config file
blastauri config init

# Validate config
blastauri config validate .blastauri.yml

# Show current config
blastauri config show
```

## Configuration

Create `.blastauri.yml` in your repository root:

```yaml
version: 1
platform: gitlab  # or github

analysis:
  ai_provider: none        # none (default), claude, or augment
  severity_threshold: low  # minimum severity to report
  post_comment: true       # post analysis as MR comment
  apply_labels: true       # apply severity labels

waf:
  provider: aws            # aws or cloudflare
  mode: log                # log (monitor) or block
  output_dir: ./terraform/waf

scanner:
  ecosystems:              # empty = auto-detect
    - npm
    - pypi
  exclude_dev: false       # include devDependencies
```

## Supported Ecosystems

| Ecosystem | Lockfiles |
|-----------|-----------|
| npm | package-lock.json, yarn.lock, pnpm-lock.yaml |
| Python | requirements.txt, Pipfile.lock, poetry.lock |
| Go | go.mod, go.sum |
| Ruby | Gemfile.lock |
| Maven | pom.xml |
| Cargo | Cargo.lock |
| Composer | composer.lock |

## Environment Variables

| Variable | Description |
|----------|-------------|
| `GITLAB_TOKEN` | GitLab API token (or use `CI_JOB_TOKEN` in CI) |
| `GITHUB_TOKEN` | GitHub API token |
| `NVD_API_KEY` | NVD API key for higher rate limits (optional, free) |

## Limitations (Honest Assessment)

- **Breaking change detection** uses 6 strategies (semver, curated database, registry metadata, API diff, heuristics, changelogs) but may miss some changes for packages without TypeScript definitions, `__all__` exports, or that aren't in our curated database.
- **CVE data** has inherent lag. NVD is often days behind initial disclosure.
- **Static analysis** won't catch dynamic imports, metaprogramming, or runtime-only usage.
- **Vulnerability reachability** requires known vulnerable function signatures. The built-in knowledge base currently includes **60 high-profile CVEs** across Python, npm, Maven, and Go. CVEs without function-level data in our knowledge base will show as "UNKNOWN" status. Dynamic dispatch and reflection may cause false negatives. Version range filtering ensures only relevant CVEs for your installed versions are checked.
- **Reachability analysis** uses full module-qualified matching (e.g., `yaml.load` not just `load`) to minimize false positives. The analysis requires calls to be resolved to their import source before matching against vulnerability signatures.
- **WAF rules** are mitigations, not fixes. They can have false positives and should be tested before deployed and monitored after being deployed.
- **API diff analysis** requires downloading package tarballs, which adds latency (~2-5s per version pair).
- **GitHub repository checks** are rate-limited without authentication (60 requests/hour). Most analyses stay well within this limit.
- **Python type analysis** requires Python 3 syntax. Python 2-only packages may have limited analysis.
- **Module name collisions** may occur in projects with duplicate filename stems (e.g., `src/utils.py` and `lib/utils.py`). The first file found is used for resolution.

## Documentation

- [Configuration Reference](docs/configuration.md)
- [GitLab Setup Guide](docs/gitlab-setup.md)
- [GitHub Setup Guide](docs/github-setup.md)
- [WAF Rules Guide](docs/waf-rules.md)
- [CI/CD Integration](docs/ci-integration.md)
- [Architecture](docs/architecture.md)
- [Troubleshooting](docs/troubleshooting.md)


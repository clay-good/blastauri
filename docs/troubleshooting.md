# Troubleshooting

Common issues and solutions when using Blastauri.

## Authentication Errors

### GitLab: 401 Unauthorized

**Symptoms:**
```
Error: 401 Unauthorized
GitLab API request failed: Invalid token
```

**Solutions:**

1. Verify token is set correctly:
   ```bash
   echo $GITLAB_TOKEN | head -c 10
   ```

2. Check token has `api` scope in GitLab > User Settings > Access Tokens

3. For CI job token, verify the job has access to the project

4. Token may have expired - create a new one

### GitHub: 401 Bad Credentials

**Symptoms:**
```
Error: Bad credentials
GitHub API request failed
```

**Solutions:**

1. Verify token is passed to the action:
   ```yaml
   - uses: clay-good/blastauri@v1
     with:
       github-token: ${{ secrets.GITHUB_TOKEN }}
   ```

2. Check workflow permissions:
   ```yaml
   permissions:
     pull-requests: write
     contents: read
   ```

3. For PAT, verify it has `repo` scope

### Permission Denied Creating Labels

**Symptoms:**
```
Error: 403 Forbidden
Cannot create label
```

**Solutions:**

1. CI job token may not have label permissions - use a PAT with `api` scope

2. Check project settings allow label creation

3. Labels may need to be created manually first

## Rate Limiting

### NVD Rate Limit Exceeded

**Symptoms:**
```
Error: 429 Too Many Requests
NVD API rate limit exceeded
```

**Solutions:**

1. Add NVD API key for higher limits:
   ```bash
   export NVD_API_KEY="your-api-key"
   ```

2. Register for free at https://nvd.nist.gov/developers/request-an-api-key

3. With API key: 50 requests per 30 seconds
   Without: 5 requests per 30 seconds

### GitLab/GitHub Rate Limits

**Symptoms:**
```
Error: 429 Rate limit exceeded
Retry-After: 60
```

**Solutions:**

1. Blastauri automatically retries with backoff

2. For persistent issues, reduce concurrent jobs

3. Use caching to reduce repeated API calls

## Pipeline Issues

### Job Not Triggering on Renovate MRs

**Symptoms:**
Pipeline doesn't run when Renovate creates MR

**Solutions:**

1. Verify rule configuration:
   ```yaml
   rules:
     - if: $CI_MERGE_REQUEST_IID && $CI_MERGE_REQUEST_SOURCE_BRANCH_NAME =~ /^renovate\//
   ```

2. Check Renovate branch naming matches `renovate/*`

3. Ensure pipeline is configured for merge request events

### Job Not Triggering on Dependabot PRs

**Symptoms:**
Workflow doesn't run for Dependabot PRs

**Solutions:**

1. Verify trigger condition:
   ```yaml
   if: github.actor == 'dependabot[bot]'
   ```

2. Check workflow runs on `pull_request` event

3. For Renovate on GitHub:
   ```yaml
   if: github.actor == 'renovate[bot]' || startsWith(github.head_ref, 'renovate/')
   ```

## Analysis Issues

### No Breaking Changes Detected

**Symptoms:**
Major version upgrade shows no breaking changes

**Solutions:**

1. Changelog may not be available for the package

2. Breaking changes detection relies on:
   - Changelog parsing
   - Release notes analysis
   - Major version heuristics

3. Review manually for packages without good changelogs

4. Consider AI-assisted analysis for complex cases

### Wrong Ecosystem Detected

**Symptoms:**
Dependencies attributed to wrong ecosystem

**Solutions:**

1. Specify ecosystems in config:
   ```yaml
   scanner:
     ecosystems:
       - npm
       - pypi
   ```

2. Check lockfile is valid and parseable

3. Multiple lockfiles may cause confusion - exclude unwanted ones

### Missing Dependencies

**Symptoms:**
Some dependencies not appearing in scan

**Solutions:**

1. Check lockfile is committed and up to date

2. Verify ecosystem is enabled in configuration

3. Dev dependencies may be excluded:
   ```yaml
   scanner:
     exclude_dev: false
   ```

4. Check exclude patterns aren't too broad

## WAF Issues

### Terraform Validation Fails

**Symptoms:**
```
Error: Invalid HCL syntax
terraform validate failed
```

**Solutions:**

1. Check Terraform version compatibility (0.13+)

2. Verify provider configuration exists

3. Review generated files for syntax errors

4. Run `terraform fmt` to fix formatting

### WAF Rules Not Applied

**Symptoms:**
Rules generated but not active in WAF

**Solutions:**

1. Run `terraform apply` after generating rules

2. Check AWS/Cloudflare credentials are configured

3. Verify WAF scope matches your use case:
   - REGIONAL for ALB/API Gateway
   - CLOUDFRONT for CloudFront distributions

### State File Conflicts

**Symptoms:**
```
Error: WAF state conflict
Rule already exists
```

**Solutions:**

1. Delete `.blastauri/waf-state.json` and regenerate

2. Sync state with actual deployed rules

3. Run `blastauri waf status` to check current state

## Docker Issues

### Image Pull Fails

**Symptoms:**
```
Error: manifest unknown
Unable to pull ghcr.io/clay-good/blastauri
```

**Solutions:**

1. Check image exists and tag is correct

2. Authenticate to GHCR:
   ```bash
   echo $GITHUB_TOKEN | docker login ghcr.io -u USERNAME --password-stdin
   ```

3. Use specific version tag instead of `latest`

### Container Permission Errors

**Symptoms:**
```
Permission denied
Cannot write to /workspace
```

**Solutions:**

1. Mount volumes with correct permissions:
   ```bash
   docker run --rm -v "$(pwd):/workspace" -u "$(id -u):$(id -g)" ghcr.io/clay-good/blastauri
   ```

2. Check SELinux/AppArmor settings on host

## CVE Cache Issues

### Cache Corruption

**Symptoms:**
```
Error: database disk image is malformed
SQLite error
```

**Solutions:**

1. Clear the cache:
   ```bash
   rm -rf ~/.cache/blastauri/
   ```

2. Cache will be rebuilt on next run

### Stale CVE Data

**Symptoms:**
Missing recent CVEs or outdated information

**Solutions:**

1. Cache TTL is 24 hours by default

2. Force cache refresh:
   ```bash
   rm ~/.cache/blastauri/cve.db
   ```

3. Check CVE sources are accessible

## Debug Mode

Enable verbose logging for troubleshooting:

### CLI

```bash
blastauri --verbose analyze --project mygroup/myproject --mr 123
```

### GitLab CI

```yaml
variables:
  BLASTAURI_LOG_LEVEL: DEBUG
```

### GitHub Actions

```yaml
- uses: clay-good/blastauri@v1
  with:
    command: analyze
  env:
    BLASTAURI_LOG_LEVEL: DEBUG
```

## Getting Help

### Logs

Collect these for bug reports:

1. Full command output with `--verbose`
2. `.blastauri.yml` configuration (redact tokens)
3. Lockfile samples (if relevant)
4. GitLab CI / GitHub Actions logs

### Reporting Issues

File issues at: https://github.com/clay-good/blastauri/issues

Include:
- Blastauri version (`blastauri --version`)
- Python version
- Platform (GitLab/GitHub)
- Steps to reproduce
- Expected vs actual behavior
- Relevant logs

## Common Error Messages

| Error | Cause | Solution |
|-------|-------|----------|
| `Token not found` | Missing environment variable | Set GITLAB_TOKEN or GITHUB_TOKEN |
| `Project not found` | Invalid project ID | Check project path format |
| `MR not found` | Invalid MR IID | Verify MR exists and is accessible |
| `No lockfiles found` | Empty or missing lockfiles | Add lockfiles to repository |
| `Parse error` | Invalid lockfile format | Check lockfile syntax |
| `Network timeout` | API unreachable | Check network/firewall settings |
| `Rate limited` | Too many API requests | Add API keys, reduce frequency |

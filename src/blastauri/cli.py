"""Command-line interface for blastauri."""

import asyncio
import json
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.table import Table

from blastauri import __version__
from blastauri.utils.logging import configure_logging, get_logger

app = typer.Typer(
    name="blastauri",
    help="Know what breaks before you merge. Analyzes Renovate/Dependabot MRs for breaking changes and manages WAF rules.",
    no_args_is_help=True,
    rich_markup_mode="rich",
)

waf_app = typer.Typer(
    name="waf",
    help="WAF rule generation and lifecycle management.",
    no_args_is_help=True,
)
app.add_typer(waf_app, name="waf")

config_app = typer.Typer(
    name="config",
    help="Configuration management.",
    no_args_is_help=True,
)
app.add_typer(config_app, name="config")

console = Console()
logger = get_logger(__name__)


def version_callback(value: bool) -> None:
    """Print version and exit."""
    if value:
        console.print(f"blastauri version {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    verbose: Annotated[
        bool,
        typer.Option(
            "--verbose",
            "-v",
            help="Enable verbose output.",
        ),
    ] = False,
    quiet: Annotated[
        bool,
        typer.Option(
            "--quiet",
            "-q",
            help="Suppress non-essential output.",
        ),
    ] = False,
    config: Annotated[
        Optional[Path],
        typer.Option(
            "--config",
            "-c",
            help="Path to configuration file.",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
        ),
    ] = None,
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            "-V",
            help="Show version and exit.",
            callback=version_callback,
            is_eager=True,
        ),
    ] = False,
) -> None:
    """Blastauri - Know what breaks before you merge."""
    log_level = "DEBUG" if verbose else "WARNING" if quiet else "INFO"
    configure_logging(level=log_level)

    if config:
        logger.debug("Using configuration file: %s", config)


@app.command()
def analyze(
    project: Annotated[
        Optional[str],
        typer.Option(
            "--project",
            "-p",
            help="GitLab project ID or path.",
        ),
    ] = None,
    mr: Annotated[
        Optional[int],
        typer.Option(
            "--mr",
            help="GitLab merge request IID.",
        ),
    ] = None,
    repo: Annotated[
        Optional[str],
        typer.Option(
            "--repo",
            help="GitHub repository (owner/repo).",
        ),
    ] = None,
    pr: Annotated[
        Optional[int],
        typer.Option(
            "--pr",
            help="GitHub pull request number.",
        ),
    ] = None,
    comment: Annotated[
        bool,
        typer.Option(
            "--comment/--no-comment",
            help="Post analysis as MR/PR comment.",
        ),
    ] = True,
    label: Annotated[
        bool,
        typer.Option(
            "--label/--no-label",
            help="Apply severity labels to MR/PR.",
        ),
    ] = True,
    ai: Annotated[
        Optional[str],
        typer.Option(
            "--ai",
            help="AI provider for enhanced analysis (claude, augment, none).",
        ),
    ] = None,
    output: Annotated[
        Optional[Path],
        typer.Option(
            "--output",
            "-o",
            help="Write report to file.",
        ),
    ] = None,
) -> None:
    """Analyze a Renovate/Dependabot merge request for breaking changes."""
    if project and mr:
        console.print(f"Analyzing GitLab MR !{mr} in project {project}...")
        # Import here to avoid circular imports
        from blastauri.analysis.ai_reviewer import AIProvider
        from blastauri.git.gitlab_client import GitLabClient, GitLabConfig
        from blastauri.git.mr_analyzer import MergeRequestAnalyzer, AnalysisConfig

        # Parse AI provider
        ai_provider = AIProvider.NONE
        if ai:
            try:
                ai_provider = AIProvider(ai.lower())
            except ValueError:
                console.print(f"[yellow]Unknown AI provider: {ai}, using none[/yellow]")

        config_obj = AnalysisConfig(
            post_comment=comment,
            apply_labels=label,
            use_ai_review=ai_provider != AIProvider.NONE,
            ai_provider=ai_provider,
        )

        # Create GitLab client from environment
        gitlab_config = GitLabConfig.from_env()
        gitlab_client = GitLabClient(gitlab_config)

        analyzer = MergeRequestAnalyzer(gitlab_client, config_obj)

        try:
            result = asyncio.run(analyzer.analyze_mr(project, mr))

            # Display results
            console.print(f"\n[bold]Analysis Complete[/bold]")
            console.print(f"Overall Severity: {result.report.overall_severity.value.upper()}")
            console.print(f"Risk Score: {result.report.overall_risk_score}/100")

            # Count totals
            total_breaking = sum(len(u.breaking_changes) for u in result.report.upgrades)
            total_cves = sum(len(u.cves_fixed) for u in result.report.upgrades)

            if total_breaking > 0:
                console.print(f"\nBreaking Changes: {total_breaking}")
                for upgrade in result.report.upgrades:
                    for change in upgrade.breaking_changes[:3]:
                        console.print(f"  - {change.description}")

            if total_cves > 0:
                console.print(f"\nCVEs Fixed: {total_cves}")
                for upgrade in result.report.upgrades:
                    for cve in upgrade.cves_fixed[:3]:
                        console.print(f"  - {cve.id}: {cve.severity.value}")

            if result.report.recommendations:
                console.print(f"\n[bold]Recommendations:[/bold]")
                for rec in result.report.recommendations[:5]:
                    console.print(f"  - {rec}")

            if result.error:
                console.print(f"[yellow]Warning: {result.error}[/yellow]")

            if output:
                report_data = {
                    "merge_request_id": result.report.merge_request_id,
                    "repository": result.report.repository,
                    "overall_risk_score": result.report.overall_risk_score,
                    "overall_severity": result.report.overall_severity.value,
                    "summary": result.report.summary,
                    "breaking_changes": total_breaking,
                    "cves_fixed": total_cves,
                    "recommendations": result.report.recommendations,
                    "labels_added": result.labels_added,
                    "should_block": result.should_block,
                }
                output.write_text(json.dumps(report_data, indent=2))
                console.print(f"\nReport written to: {output}")

            # Apply results to MR
            if comment or label:
                await_result = asyncio.run(
                    analyzer.apply_analysis_result(project, mr, result)
                )
                if comment and result.comment_body:
                    console.print("[green]Analysis comment posted[/green]")
                if label and result.labels_added:
                    console.print(f"[green]Labels applied: {', '.join(result.labels_added)}[/green]")

            # Exit with error if should block
            if result.should_block:
                console.print(f"\n[red]MR blocked due to {result.report.overall_severity.value} severity[/red]")
                raise typer.Exit(code=1)

        except typer.Exit:
            raise
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
            logger.exception("Analysis failed")
            raise typer.Exit(code=1)

    elif repo and pr:
        console.print(f"Analyzing GitHub PR #{pr} in {repo}...")
        from blastauri.analysis.ai_reviewer import AIProvider
        from blastauri.git.github_client import GitHubClient, GitHubConfig
        from blastauri.git.pr_analyzer import PullRequestAnalyzer, PRAnalysisConfig

        # Parse AI provider
        ai_provider = AIProvider.NONE
        if ai:
            try:
                ai_provider = AIProvider(ai.lower())
            except ValueError:
                console.print(f"[yellow]Unknown AI provider: {ai}, using none[/yellow]")

        config_obj = PRAnalysisConfig(
            post_comment=comment,
            apply_labels=label,
            use_ai_review=ai_provider != AIProvider.NONE,
            ai_provider=ai_provider,
        )

        # Create GitHub client from environment
        github_config = GitHubConfig.from_env()
        github_client = GitHubClient(github_config)

        analyzer = PullRequestAnalyzer(github_client, config_obj)

        try:
            result = asyncio.run(analyzer.analyze_pr(repo, pr))

            # Display results
            console.print(f"\n[bold]Analysis Complete[/bold]")
            console.print(f"Overall Severity: {result.report.overall_severity.value.upper()}")
            console.print(f"Risk Score: {result.report.overall_risk_score}/100")

            # Count totals
            total_breaking = sum(len(u.breaking_changes) for u in result.report.upgrades)
            total_cves = sum(len(u.cves_fixed) for u in result.report.upgrades)

            if total_breaking > 0:
                console.print(f"\nBreaking Changes: {total_breaking}")
                for upgrade in result.report.upgrades:
                    for change in upgrade.breaking_changes[:3]:
                        console.print(f"  - {change.description}")

            if total_cves > 0:
                console.print(f"\nCVEs Fixed: {total_cves}")
                for upgrade in result.report.upgrades:
                    for cve in upgrade.cves_fixed[:3]:
                        console.print(f"  - {cve.id}: {cve.severity.value}")

            if result.report.recommendations:
                console.print(f"\n[bold]Recommendations:[/bold]")
                for rec in result.report.recommendations[:5]:
                    console.print(f"  - {rec}")

            if result.error:
                console.print(f"[yellow]Warning: {result.error}[/yellow]")

            if output:
                report_data = {
                    "pull_request_number": result.report.merge_request_id,
                    "repository": result.report.repository,
                    "overall_risk_score": result.report.overall_risk_score,
                    "overall_severity": result.report.overall_severity.value,
                    "summary": result.report.summary,
                    "breaking_changes": total_breaking,
                    "cves_fixed": total_cves,
                    "recommendations": result.report.recommendations,
                    "labels_added": result.labels_added,
                    "should_fail": result.should_fail,
                }
                output.write_text(json.dumps(report_data, indent=2))
                console.print(f"\nReport written to: {output}")

            # Apply results to PR
            if comment or label:
                await_result = asyncio.run(
                    analyzer.apply_analysis_result(repo, pr, result)
                )
                if comment and result.comment_body:
                    console.print("[green]Analysis comment posted[/green]")
                if label and result.labels_added:
                    console.print(f"[green]Labels applied: {', '.join(result.labels_added)}[/green]")

            # Exit with error if should fail
            if result.should_fail:
                console.print(f"\n[red]PR check failed due to {result.report.overall_severity.value} severity[/red]")
                raise typer.Exit(code=1)

        except typer.Exit:
            raise
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
            logger.exception("Analysis failed")
            raise typer.Exit(code=1)
    else:
        console.print(
            "[bold red]Error:[/bold red] Must specify either --project/--mr or --repo/--pr",
            style="red",
        )
        raise typer.Exit(code=1)


@app.command()
def scan(
    path: Annotated[
        Path,
        typer.Argument(
            help="Path to directory to scan for dependencies.",
            exists=True,
            file_okay=False,
            dir_okay=True,
            readable=True,
        ),
    ] = Path("."),
    format: Annotated[
        str,
        typer.Option(
            "--format",
            "-f",
            help="Output format (table, json, sarif).",
        ),
    ] = "table",
    output: Annotated[
        Optional[Path],
        typer.Option(
            "--output",
            "-o",
            help="Write results to file.",
        ),
    ] = None,
    severity: Annotated[
        str,
        typer.Option(
            "--severity",
            "-s",
            help="Minimum severity to report (critical, high, medium, low).",
        ),
    ] = "low",
) -> None:
    """Scan a directory for dependencies and known vulnerabilities."""
    console.print(f"Scanning {path} for dependencies...")

    from blastauri.scanners.detector import detect_ecosystems, get_scanners

    try:
        # Detect ecosystems
        ecosystems = detect_ecosystems(str(path))

        if not ecosystems:
            console.print("[yellow]No supported lockfiles found.[/yellow]")
            raise typer.Exit(code=0)

        console.print(f"Detected ecosystems: {', '.join(e.value for e in ecosystems)}")

        # Get scanners and scan
        scanners = get_scanners(str(path))
        all_dependencies = []

        for scanner in scanners:
            result = scanner.scan_directory(str(path))
            all_dependencies.extend(result.dependencies)

        console.print(f"Found {len(all_dependencies)} dependencies")

        if format == "table":
            table = Table(title="Dependencies")
            table.add_column("Name", style="cyan")
            table.add_column("Version", style="green")
            table.add_column("Ecosystem", style="yellow")
            table.add_column("Direct", style="blue")

            for dep in all_dependencies[:50]:  # Limit display
                table.add_row(
                    dep.name,
                    dep.version,
                    dep.ecosystem.value,
                    "Yes" if dep.is_direct else "No",
                )

            console.print(table)

            if len(all_dependencies) > 50:
                console.print(f"... and {len(all_dependencies) - 50} more")

        elif format == "json":
            result_data = {
                "dependencies": [
                    {
                        "name": d.name,
                        "version": d.version,
                        "ecosystem": d.ecosystem.value,
                        "is_direct": d.is_direct,
                        "is_dev": d.is_dev,
                    }
                    for d in all_dependencies
                ],
                "total": len(all_dependencies),
            }

            if output:
                output.write_text(json.dumps(result_data, indent=2))
                console.print(f"Results written to: {output}")
            else:
                console.print(json.dumps(result_data, indent=2))

    except Exception as e:
        console.print(f"[red]Scan error: {e}[/red]")
        raise typer.Exit(code=1)


@waf_app.command("generate")
def waf_generate(
    path: Annotated[
        Path,
        typer.Argument(
            help="Path to directory containing lockfiles.",
            exists=True,
            file_okay=False,
            dir_okay=True,
            readable=True,
        ),
    ] = Path("."),
    provider: Annotated[
        str,
        typer.Option(
            "--provider",
            help="WAF provider (aws, cloudflare, both).",
        ),
    ] = "aws",
    mode: Annotated[
        str,
        typer.Option(
            "--mode",
            help="WAF rule mode (log, block).",
        ),
    ] = "log",
    output: Annotated[
        Optional[Path],
        typer.Option(
            "--output",
            "-o",
            help="Output directory for Terraform files.",
        ),
    ] = None,
    cves: Annotated[
        Optional[str],
        typer.Option(
            "--cves",
            help="Comma-separated list of CVE IDs to generate rules for.",
        ),
    ] = None,
    owasp: Annotated[
        bool,
        typer.Option(
            "--owasp",
            help="Generate OWASP Top 10 protection rules.",
        ),
    ] = False,
    critical_only: Annotated[
        bool,
        typer.Option(
            "--critical-only",
            help="Only generate rules for critical CVEs.",
        ),
    ] = False,
) -> None:
    """Generate WAF rules based on detected vulnerabilities."""
    from blastauri.waf.generator import (
        WafGenerator,
        WafGeneratorConfig,
        generate_owasp_rules,
    )
    from blastauri.waf.providers.base import WafProviderType, WafRuleMode

    console.print(f"Generating WAF rules...")
    console.print(f"Provider: {provider}")
    console.print(f"Mode: {mode}")

    try:
        # Parse provider
        if provider == "aws":
            waf_provider = WafProviderType.AWS
        elif provider == "cloudflare":
            waf_provider = WafProviderType.CLOUDFLARE
        else:
            console.print(f"[red]Unsupported provider: {provider}[/red]")
            raise typer.Exit(code=1)

        # Parse mode
        waf_mode = WafRuleMode.BLOCK if mode == "block" else WafRuleMode.LOG

        # Determine output directory
        output_dir = str(output) if output else None

        config = WafGeneratorConfig(
            provider=waf_provider,
            mode=waf_mode,
            output_dir=output_dir,
            include_critical_only=critical_only,
        )

        generator = WafGenerator(config)

        if owasp:
            console.print("Generating OWASP Top 10 protection rules...")
            result = generator.generate_owasp_protection()
        elif cves:
            cve_list = [c.strip() for c in cves.split(",")]
            console.print(f"Generating rules for CVEs: {', '.join(cve_list)}")
            result = generator.generate_from_cves(cve_list)
        elif critical_only:
            console.print("Generating rules for critical CVEs...")
            result = generator.generate_critical_protection()
        else:
            # Default: generate for all critical templates
            result = generator.generate_critical_protection()

        # Display results
        console.print(f"\n[bold]Generation Complete[/bold]")
        console.print(f"Rules generated: {result.rules_count}")
        console.print(f"Templates used: {len(result.templates_used)}")

        if result.cves_covered:
            console.print(f"CVEs covered: {', '.join(result.cves_covered[:5])}")
            if len(result.cves_covered) > 5:
                console.print(f"  ... and {len(result.cves_covered) - 5} more")

        if result.warnings:
            console.print("\n[yellow]Warnings:[/yellow]")
            for warning in result.warnings:
                console.print(f"  - {warning}")

        # Display generated files
        if result.files:
            console.print("\n[bold]Generated Files:[/bold]")
            for tf_file in result.files:
                if output_dir:
                    console.print(f"  - {output_dir}/{tf_file.filename}")
                else:
                    console.print(f"\n--- {tf_file.filename} ---")
                    console.print(tf_file.content[:500])
                    if len(tf_file.content) > 500:
                        console.print("... (truncated)")

    except Exception as e:
        console.print(f"[red]Generation error: {e}[/red]")
        raise typer.Exit(code=1)


@waf_app.command("sync")
def waf_sync(
    path: Annotated[
        Path,
        typer.Argument(
            help="Path to repository root.",
            exists=True,
            file_okay=False,
            dir_okay=True,
            readable=True,
        ),
    ] = Path("."),
    project: Annotated[
        Optional[str],
        typer.Option(
            "--project",
            "-p",
            help="GitLab project ID or path.",
        ),
    ] = None,
    repo: Annotated[
        Optional[str],
        typer.Option(
            "--repo",
            help="GitHub repository (owner/repo).",
        ),
    ] = None,
    create_mr: Annotated[
        bool,
        typer.Option(
            "--create-mr/--no-mr",
            help="Create merge request with WAF changes.",
        ),
    ] = True,
    provider: Annotated[
        str,
        typer.Option(
            "--provider",
            help="WAF provider (aws, cloudflare).",
        ),
    ] = "aws",
    output_dir: Annotated[
        str,
        typer.Option(
            "--output-dir",
            help="Directory for Terraform files.",
        ),
    ] = "terraform/waf",
    auto_promote: Annotated[
        bool,
        typer.Option(
            "--auto-promote",
            help="Automatically promote eligible rules to block mode.",
        ),
    ] = False,
) -> None:
    """Synchronize WAF rules with current dependency state."""
    from blastauri.core.waf_orchestrator import WafSyncOrchestrator, WafSyncConfig
    from blastauri.waf.providers.base import WafProviderType, WafRuleMode

    console.print("Synchronizing WAF rules...")
    console.print(f"Repository: {path}")
    console.print(f"Provider: {provider}")

    try:
        # Parse provider
        if provider == "aws":
            waf_provider = WafProviderType.AWS
        elif provider == "cloudflare":
            waf_provider = WafProviderType.CLOUDFLARE
        else:
            console.print(f"[red]Unsupported provider: {provider}[/red]")
            raise typer.Exit(code=1)

        config = WafSyncConfig(
            provider=waf_provider,
            mode=WafRuleMode.LOG,
            output_dir=output_dir,
            create_mr=create_mr and (project is not None or repo is not None),
            auto_promote=auto_promote,
        )

        orchestrator = WafSyncOrchestrator(str(path), config)

        # For now, just show the current status
        # Full sync requires scanning and CVE detection
        status = orchestrator.get_status()

        console.print(f"\n[bold]Current WAF Status[/bold]")
        console.print(f"Provider: {status['provider']}")
        console.print(f"Last sync: {status['last_sync'] or 'Never'}")
        console.print(f"Total rules: {status['total_rules']}")
        console.print(f"Active rules: {status['active_rules']}")
        console.print(f"  - Log mode: {status['log_mode_rules']}")
        console.print(f"  - Block mode: {status['block_mode_rules']}")
        console.print(f"Obsolete rules: {status['obsolete_rules']}")

        if status['cves_covered']:
            console.print(f"\nCVEs covered: {', '.join(status['cves_covered'][:5])}")
            if len(status['cves_covered']) > 5:
                console.print(f"  ... and {len(status['cves_covered']) - 5} more")

        if status['rules']:
            console.print("\n[bold]Rules:[/bold]")
            table = Table()
            table.add_column("Rule ID", style="cyan")
            table.add_column("CVEs", style="yellow")
            table.add_column("Mode", style="green")
            table.add_column("Status", style="blue")

            for rule in status['rules'][:10]:
                table.add_row(
                    rule['rule_id'],
                    ', '.join(rule['cve_ids'][:2]),
                    rule['mode'],
                    rule['status'],
                )

            console.print(table)

        console.print("\n[dim]Run with --project or --repo to create MRs for changes.[/dim]")

    except Exception as e:
        console.print(f"[red]Sync error: {e}[/red]")
        raise typer.Exit(code=1)


@waf_app.command("status")
def waf_status(
    path: Annotated[
        Path,
        typer.Argument(
            help="Path to directory containing WAF state.",
            exists=True,
            file_okay=False,
            dir_okay=True,
            readable=True,
        ),
    ] = Path("."),
    format: Annotated[
        str,
        typer.Option(
            "--format",
            "-f",
            help="Output format (table, json).",
        ),
    ] = "table",
) -> None:
    """Show current WAF rule status."""
    from blastauri.waf.lifecycle import WafLifecycleManager
    from blastauri.waf.providers.base import WafProviderType

    console.print(f"Loading WAF status from {path}...")

    try:
        manager = WafLifecycleManager(str(path), WafProviderType.AWS)
        state = manager.load_state()
        status = manager.get_status_report(state)

        if format == "json":
            console.print(json.dumps(status, indent=2))
            return

        # Table format
        console.print(f"\n[bold]WAF Rule Status[/bold]")
        console.print(f"Provider: {status['provider']}")
        console.print(f"Last sync: {status['last_sync'] or 'Never'}")
        console.print("")

        # Summary table
        summary_table = Table(title="Summary")
        summary_table.add_column("Metric", style="cyan")
        summary_table.add_column("Count", style="green", justify="right")

        summary_table.add_row("Total Rules", str(status['total_rules']))
        summary_table.add_row("Active Rules", str(status['active_rules']))
        summary_table.add_row("Log Mode", str(status['log_mode_rules']))
        summary_table.add_row("Block Mode", str(status['block_mode_rules']))
        summary_table.add_row("Obsolete Rules", str(status['obsolete_rules']))
        summary_table.add_row("CVEs Covered", str(len(status['cves_covered'])))

        console.print(summary_table)

        # Rules table
        if status['rules']:
            console.print("")
            rules_table = Table(title="Rules")
            rules_table.add_column("Rule ID", style="cyan")
            rules_table.add_column("CVEs", style="yellow")
            rules_table.add_column("Mode", style="green")
            rules_table.add_column("Status", style="blue")
            rules_table.add_column("Package", style="magenta")
            rules_table.add_column("Created", style="dim")

            for rule in status['rules']:
                cves = ', '.join(rule['cve_ids'][:2])
                if len(rule['cve_ids']) > 2:
                    cves += f" +{len(rule['cve_ids']) - 2}"

                created = rule['created_at'][:10] if rule['created_at'] else 'N/A'

                rules_table.add_row(
                    rule['rule_id'],
                    cves,
                    rule['mode'],
                    rule['status'],
                    rule['package'],
                    created,
                )

            console.print(rules_table)

        # Promotion candidates
        candidates = manager.find_promotion_candidates(state)
        if candidates:
            console.print(f"\n[yellow]Promotion Candidates ({len(candidates)}):[/yellow]")
            for rule in candidates:
                console.print(f"  - {rule.rule_id}: Ready to promote to block mode")

        # Obsolete rules
        # Note: Full obsolete check requires current dependencies
        obsolete = [r for r in state.rules if r.status == "obsolete"]
        if obsolete:
            console.print(f"\n[yellow]Obsolete Rules ({len(obsolete)}):[/yellow]")
            for rule in obsolete:
                console.print(f"  - {rule.rule_id}: Can be removed")

    except Exception as e:
        console.print(f"[red]Status error: {e}[/red]")
        raise typer.Exit(code=1)


@waf_app.command("templates")
def waf_templates() -> None:
    """List available WAF rule templates."""
    from blastauri.waf.rule_templates import get_default_registry

    registry = get_default_registry()
    templates = registry.get_all_templates()

    table = Table(title="Available WAF Rule Templates")
    table.add_column("ID", style="cyan")
    table.add_column("Name", style="green")
    table.add_column("Category", style="yellow")
    table.add_column("Severity", style="red")
    table.add_column("CVEs", style="blue")

    for template in templates:
        cves = ', '.join(template.cve_ids[:2]) if template.cve_ids else '-'
        if len(template.cve_ids) > 2:
            cves += f" +{len(template.cve_ids) - 2}"

        table.add_row(
            template.template_id,
            template.name,
            template.category.value,
            template.severity,
            cves,
        )

    console.print(table)
    console.print(f"\nTotal: {len(templates)} templates available")


@config_app.command("init")
def config_init(
    path: Annotated[
        Path,
        typer.Argument(
            help="Directory to create configuration file in.",
        ),
    ] = Path("."),
    force: Annotated[
        bool,
        typer.Option(
            "--force",
            "-f",
            help="Overwrite existing configuration file.",
        ),
    ] = False,
) -> None:
    """Initialize a new configuration file."""
    config_path = path / ".blastauri.yml"

    if config_path.exists() and not force:
        console.print(f"[yellow]Configuration file already exists: {config_path}[/yellow]")
        console.print("Use --force to overwrite.")
        raise typer.Exit(code=1)

    default_config = """# Blastauri Configuration
# https://github.com/clay-good/blastauri

version: 1

# Platform settings
platform: gitlab  # gitlab or github

# Analysis settings
analysis:
  ai_provider: none  # none, claude, augment
  severity_threshold: low  # critical, high, medium, low
  post_comment: true
  apply_labels: true

# WAF settings
waf:
  provider: aws  # aws, cloudflare
  mode: log  # log, block
  output_dir: ./terraform/waf
  promotion_days: 14

# Scanner settings
scanner:
  ecosystems: []  # empty = auto-detect
  exclude_dev: false
  exclude_patterns:
    - "**/node_modules/**"
    - "**/vendor/**"
    - "**/.git/**"
"""

    config_path.write_text(default_config)
    console.print(f"Created configuration file: {config_path}")


@config_app.command("validate")
def config_validate(
    config: Annotated[
        Path,
        typer.Argument(
            help="Path to configuration file to validate.",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
        ),
    ],
) -> None:
    """Validate a configuration file."""
    import yaml

    console.print(f"Validating configuration file: {config}...")

    try:
        content = config.read_text()
        data = yaml.safe_load(content)

        errors = []
        warnings = []

        # Check version
        if "version" not in data:
            warnings.append("Missing 'version' field")
        elif data["version"] != 1:
            warnings.append(f"Unknown version: {data['version']}")

        # Check platform
        if "platform" in data:
            if data["platform"] not in ["gitlab", "github"]:
                errors.append(f"Invalid platform: {data['platform']}")

        # Check analysis settings
        if "analysis" in data:
            analysis = data["analysis"]
            if "ai_provider" in analysis:
                if analysis["ai_provider"] not in ["none", "claude", "augment"]:
                    errors.append(f"Invalid ai_provider: {analysis['ai_provider']}")
            if "severity_threshold" in analysis:
                if analysis["severity_threshold"] not in ["critical", "high", "medium", "low"]:
                    errors.append(f"Invalid severity_threshold: {analysis['severity_threshold']}")

        # Check WAF settings
        if "waf" in data:
            waf = data["waf"]
            if "provider" in waf:
                if waf["provider"] not in ["aws", "cloudflare"]:
                    errors.append(f"Invalid WAF provider: {waf['provider']}")
            if "mode" in waf:
                if waf["mode"] not in ["log", "block"]:
                    errors.append(f"Invalid WAF mode: {waf['mode']}")

        # Report results
        if errors:
            console.print("[red]Validation failed:[/red]")
            for error in errors:
                console.print(f"  [red]ERROR:[/red] {error}")
            raise typer.Exit(code=1)

        if warnings:
            console.print("[yellow]Warnings:[/yellow]")
            for warning in warnings:
                console.print(f"  [yellow]WARNING:[/yellow] {warning}")

        console.print("[green]Configuration is valid.[/green]")

    except yaml.YAMLError as e:
        console.print(f"[red]YAML parse error: {e}[/red]")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[red]Validation error: {e}[/red]")
        raise typer.Exit(code=1)


@config_app.command("show")
def config_show(
    config: Annotated[
        Optional[Path],
        typer.Option(
            "--config",
            "-c",
            help="Path to configuration file.",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
        ),
    ] = None,
) -> None:
    """Show current configuration."""
    import yaml

    # Find config file
    if config:
        config_path = config
    else:
        # Search for config file
        search_paths = [
            Path(".blastauri.yml"),
            Path(".blastauri.yaml"),
            Path("blastauri.yml"),
            Path("blastauri.yaml"),
        ]
        config_path = None
        for p in search_paths:
            if p.exists():
                config_path = p
                break

    if config_path is None or not config_path.exists():
        console.print("[yellow]No configuration file found.[/yellow]")
        console.print("Run 'blastauri config init' to create one.")
        raise typer.Exit(code=0)

    console.print(f"Configuration file: {config_path}\n")

    try:
        content = config_path.read_text()
        data = yaml.safe_load(content)

        # Display as formatted table
        table = Table(title="Configuration")
        table.add_column("Setting", style="cyan")
        table.add_column("Value", style="green")

        def flatten_dict(d: dict, prefix: str = "") -> list:
            items = []
            for key, value in d.items():
                full_key = f"{prefix}.{key}" if prefix else key
                if isinstance(value, dict):
                    items.extend(flatten_dict(value, full_key))
                elif isinstance(value, list):
                    items.append((full_key, ", ".join(str(v) for v in value) or "(empty)"))
                else:
                    items.append((full_key, str(value)))
            return items

        for key, value in flatten_dict(data):
            table.add_row(key, value)

        console.print(table)

    except yaml.YAMLError as e:
        console.print(f"[red]YAML parse error: {e}[/red]")
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()

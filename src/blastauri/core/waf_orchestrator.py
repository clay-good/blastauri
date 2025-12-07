"""WAF sync orchestrator.

Coordinates the full WAF synchronization workflow:
1. Load current WAF state
2. Scan dependencies
3. Query for CVEs
4. Analyze lifecycle changes
5. Generate Terraform
6. Create MR with changes
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

from blastauri.core.models import CVE, Dependency
from blastauri.waf.lifecycle import (
    LifecycleAnalysis,
    WafLifecycleManager,
    WafState,
)
from blastauri.waf.providers.base import WafProviderType, WafRuleMode

if TYPE_CHECKING:
    from blastauri.waf.generator import (
        GenerationResult,
    )


@dataclass
class WafSyncConfig:
    """Configuration for WAF sync operation."""

    provider: WafProviderType = WafProviderType.AWS
    mode: WafRuleMode = WafRuleMode.LOG
    output_dir: str = "./terraform/waf"
    promotion_days: int = 14
    create_mr: bool = True
    auto_promote: bool = False
    name_prefix: str = "blastauri"


@dataclass
class WafSyncResult:
    """Result of WAF sync operation."""

    success: bool
    analysis: LifecycleAnalysis | None
    terraform_files: list[str]
    mr_created: bool
    mr_url: str | None
    new_state: WafState | None
    errors: list[str]
    summary: str


class WafSyncOrchestrator:
    """Orchestrates WAF rule synchronization.

    Coordinates scanning, CVE detection, lifecycle analysis,
    Terraform generation, and MR creation.
    """

    def __init__(
        self,
        repo_path: str,
        config: WafSyncConfig | None = None,
    ) -> None:
        """Initialize the orchestrator.

        Args:
            repo_path: Path to the repository.
            config: Sync configuration.
        """
        self._repo_path = Path(repo_path)
        self._config = config or WafSyncConfig()
        self._lifecycle = WafLifecycleManager(
            repo_path=repo_path,
            provider=self._config.provider,
            promotion_days=self._config.promotion_days,
        )

    async def sync(
        self,
        dependencies: list[Dependency],
        cves: list[CVE],
        fixed_versions: dict[str, str],
        git_client: object | None = None,
        project_id: str | None = None,
    ) -> WafSyncResult:
        """Execute full WAF sync workflow.

        Args:
            dependencies: Current dependencies from scanner.
            cves: CVEs detected in dependencies.
            fixed_versions: Map of CVE ID to fixed version.
            git_client: GitLab or GitHub client for MR creation.
            project_id: Project/repo identifier for MR creation.

        Returns:
            WafSyncResult with operation outcome.
        """
        errors: list[str] = []
        terraform_files: list[str] = []

        try:
            # Step 1: Load current WAF state
            current_state = self._lifecycle.load_state()

            # Step 2: Analyze lifecycle
            analysis = self._lifecycle.analyze_lifecycle(
                current_state=current_state,
                dependencies=dependencies,
                detected_cves=cves,
                fixed_versions=fixed_versions,
            )

            # Step 3: Check if any changes needed
            has_changes = (
                len(analysis.new_rules) > 0
                or len(analysis.obsolete_rules) > 0
                or (self._config.auto_promote and len(analysis.promotion_candidates) > 0)
            )

            if not has_changes:
                return WafSyncResult(
                    success=True,
                    analysis=analysis,
                    terraform_files=[],
                    mr_created=False,
                    mr_url=None,
                    new_state=current_state,
                    errors=[],
                    summary="No WAF rule changes needed",
                )

            # Step 4: Apply changes to state
            new_state = self._lifecycle.apply_changes(current_state, analysis)

            # Step 5: Handle promotions if auto-promote enabled
            if self._config.auto_promote:
                for candidate in analysis.promotion_candidates:
                    self._lifecycle.promote_rule(new_state, candidate.rule_id)

            # Step 6: Generate Terraform
            waf_cves = [
                cve for cve in cves
                if cve.is_waf_mitigatable
            ]

            if waf_cves or analysis.new_rules:
                gen_result = self._generate_terraform(waf_cves, analysis)
                terraform_files = [f.filename for f in gen_result.files]

                # Write Terraform files
                self._write_terraform_files(gen_result)

            # Step 7: Save state
            self._lifecycle.save_state(new_state)

            # Step 8: Create MR if configured
            mr_created = False
            mr_url = None

            if self._config.create_mr and git_client and project_id and has_changes:
                mr_result = await self._create_mr(
                    git_client=git_client,
                    project_id=project_id,
                    analysis=analysis,
                    terraform_files=terraform_files,
                )
                mr_created = mr_result.get("created", False)
                mr_url = mr_result.get("url")
                if mr_result.get("error"):
                    errors.append(mr_result["error"])

            # Generate summary
            summary = self._generate_sync_summary(
                analysis=analysis,
                terraform_files=terraform_files,
                mr_created=mr_created,
                mr_url=mr_url,
            )

            return WafSyncResult(
                success=True,
                analysis=analysis,
                terraform_files=terraform_files,
                mr_created=mr_created,
                mr_url=mr_url,
                new_state=new_state,
                errors=errors,
                summary=summary,
            )

        except Exception as e:
            errors.append(str(e))
            return WafSyncResult(
                success=False,
                analysis=None,
                terraform_files=[],
                mr_created=False,
                mr_url=None,
                new_state=None,
                errors=errors,
                summary=f"WAF sync failed: {e}",
            )

    def _generate_terraform(
        self,
        cves: list[CVE],
        analysis: LifecycleAnalysis,
    ) -> GenerationResult:
        """Generate Terraform for WAF rules.

        Args:
            cves: CVEs to generate rules for.
            analysis: Lifecycle analysis.

        Returns:
            Terraform generation result.
        """
        # Import at runtime to avoid circular imports
        from blastauri.waf.generator import WafGenerator, WafGeneratorConfig

        # Get CVE IDs from new rules
        cve_ids = []
        for change in analysis.new_rules:
            cve_ids.extend(change.cve_ids)

        # Add CVE IDs from unchanged active rules
        for rule in analysis.unchanged_rules:
            cve_ids.extend(rule.cve_ids)

        # Deduplicate
        cve_ids = list(set(cve_ids))

        config = WafGeneratorConfig(
            provider=self._config.provider,
            mode=self._config.mode,
            name_prefix=self._config.name_prefix,
        )

        generator = WafGenerator(config)
        return generator.generate_from_cves(cve_ids, name="waf-rules")

    def _write_terraform_files(self, result: GenerationResult) -> None:
        """Write Terraform files to output directory.

        Args:
            result: Generation result with files.
        """
        output_path = self._repo_path / self._config.output_dir
        output_path.mkdir(parents=True, exist_ok=True)

        for tf_file in result.files:
            file_path = output_path / tf_file.filename
            file_path.write_text(tf_file.content)

    async def _create_mr(
        self,
        git_client: object,
        project_id: str,
        analysis: LifecycleAnalysis,
        terraform_files: list[str],
    ) -> dict:
        """Create MR with WAF changes.

        Args:
            git_client: Git platform client.
            project_id: Project identifier.
            analysis: Lifecycle analysis.
            terraform_files: List of Terraform files changed.

        Returns:
            Dict with created, url, and error keys.
        """
        try:
            # Generate branch name
            timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
            branch_name = f"blastauri/waf-update-{timestamp}"

            # Generate MR description
            description = self._generate_mr_description(analysis, terraform_files)

            # Generate title
            title = self._generate_mr_title(analysis)

            # Check if client has required methods
            if hasattr(git_client, "create_branch"):
                # GitLab client
                await self._create_gitlab_mr(
                    client=git_client,
                    project_id=project_id,
                    branch_name=branch_name,
                    title=title,
                    description=description,
                    terraform_files=terraform_files,
                )
                return {"created": True, "url": None}

            elif hasattr(git_client, "get_repo"):
                # GitHub client
                await self._create_github_pr(
                    client=git_client,
                    repo=project_id,
                    branch_name=branch_name,
                    title=title,
                    description=description,
                    terraform_files=terraform_files,
                )
                return {"created": True, "url": None}

            else:
                return {"created": False, "error": "Unsupported git client"}

        except Exception as e:
            return {"created": False, "error": str(e)}

    async def _create_gitlab_mr(
        self,
        client: object,
        project_id: str,
        branch_name: str,
        title: str,
        description: str,
        terraform_files: list[str],
    ) -> None:
        """Create GitLab MR.

        Args:
            client: GitLab client.
            project_id: Project ID.
            branch_name: Branch name.
            title: MR title.
            description: MR description.
            terraform_files: Files to commit.
        """
        # Create branch
        if hasattr(client, "create_branch"):
            await client.create_branch(project_id, branch_name, "main")

        # Commit files
        output_dir = self._repo_path / self._config.output_dir
        for filename in terraform_files:
            file_path = output_dir / filename
            if file_path.exists():
                content = file_path.read_text()
                tf_path = f"{self._config.output_dir}/{filename}"
                if hasattr(client, "create_file"):
                    await client.create_file(
                        project_id,
                        tf_path,
                        branch_name,
                        content,
                        f"chore(waf): update WAF rules - {filename}",
                    )

        # Commit state file
        state_path = self._lifecycle.state_file_path
        if state_path.exists():
            state_content = state_path.read_text()
            if hasattr(client, "create_file"):
                await client.create_file(
                    project_id,
                    str(state_path.relative_to(self._repo_path)),
                    branch_name,
                    state_content,
                    "chore(waf): update WAF state",
                )

        # Create MR
        if hasattr(client, "create_merge_request"):
            await client.create_merge_request(
                project_id,
                branch_name,
                "main",
                title,
                description,
            )

    async def _create_github_pr(
        self,
        client: object,
        repo: str,
        branch_name: str,
        title: str,
        description: str,
        terraform_files: list[str],
    ) -> None:
        """Create GitHub PR.

        Args:
            client: GitHub client.
            repo: Repository name.
            branch_name: Branch name.
            title: PR title.
            description: PR description.
            terraform_files: Files to commit.
        """
        # Implementation depends on GitHub client interface
        # This would use PyGithub or similar
        pass

    def _generate_mr_title(self, analysis: LifecycleAnalysis) -> str:
        """Generate MR title.

        Args:
            analysis: Lifecycle analysis.

        Returns:
            MR title string.
        """
        parts = []

        if analysis.new_rules:
            parts.append(f"add {len(analysis.new_rules)} rule(s)")

        if analysis.obsolete_rules:
            parts.append(f"remove {len(analysis.obsolete_rules)} obsolete rule(s)")

        if analysis.promotion_candidates and self._config.auto_promote:
            parts.append(f"promote {len(analysis.promotion_candidates)} rule(s)")

        if not parts:
            return "chore(waf): update WAF rules"

        return f"chore(waf): {', '.join(parts)}"

    def _generate_mr_description(
        self,
        analysis: LifecycleAnalysis,
        terraform_files: list[str],
    ) -> str:
        """Generate MR description.

        Args:
            analysis: Lifecycle analysis.
            terraform_files: List of changed files.

        Returns:
            MR description in markdown.
        """
        lines = []
        lines.append("## WAF Rule Update")
        lines.append("")
        lines.append("This MR was automatically generated by Blastauri.")
        lines.append("")

        if analysis.new_rules:
            lines.append("### New Rules")
            lines.append("")
            for change in analysis.new_rules:
                cves = ", ".join(change.cve_ids)
                lines.append(f"- **{change.rule_id}**: {cves}")
                lines.append(f"  - Reason: {change.reason}")
            lines.append("")

        if analysis.obsolete_rules:
            lines.append("### Obsolete Rules (to be removed)")
            lines.append("")
            for change in analysis.obsolete_rules:
                cves = ", ".join(change.cve_ids)
                lines.append(f"- **{change.rule_id}**: {cves}")
                lines.append(f"  - Reason: {change.reason}")
            lines.append("")

        if analysis.promotion_candidates:
            lines.append("### Promotion Candidates")
            lines.append("")
            if self._config.auto_promote:
                lines.append("The following rules have been promoted to block mode:")
            else:
                lines.append("The following rules are ready for promotion to block mode:")
            lines.append("")
            for change in analysis.promotion_candidates:
                lines.append(f"- **{change.rule_id}**")
                lines.append(f"  - Reason: {change.reason}")
            lines.append("")

        if terraform_files:
            lines.append("### Changed Files")
            lines.append("")
            for filename in terraform_files:
                lines.append(f"- `{self._config.output_dir}/{filename}`")
            lines.append("- `.blastauri/waf-state.json`")
            lines.append("")

        lines.append("### Review Checklist")
        lines.append("")
        lines.append("- [ ] Reviewed WAF rule patterns")
        lines.append("- [ ] Verified Terraform syntax")
        lines.append("- [ ] Tested in staging environment")
        lines.append("")
        lines.append("---")
        lines.append("*Generated by [Blastauri](https://github.com/clay-good/blastauri)*")

        return "\n".join(lines)

    def _generate_sync_summary(
        self,
        analysis: LifecycleAnalysis,
        terraform_files: list[str],
        mr_created: bool,
        mr_url: str | None,
    ) -> str:
        """Generate sync operation summary.

        Args:
            analysis: Lifecycle analysis.
            terraform_files: Generated Terraform files.
            mr_created: Whether MR was created.
            mr_url: URL of created MR.

        Returns:
            Summary string.
        """
        lines = []
        lines.append("WAF Sync Complete")
        lines.append("")

        if analysis.new_rules:
            lines.append(f"  Added {len(analysis.new_rules)} new rule(s)")
        if analysis.obsolete_rules:
            lines.append(f"  Marked {len(analysis.obsolete_rules)} rule(s) obsolete")
        if analysis.promotion_candidates:
            lines.append(
                f"  {len(analysis.promotion_candidates)} rule(s) ready for promotion"
            )

        if terraform_files:
            lines.append(f"  Generated {len(terraform_files)} Terraform file(s)")

        if mr_created:
            lines.append(f"  Created MR: {mr_url or 'pending'}")
        else:
            lines.append("  No MR created")

        return "\n".join(lines)

    def get_status(self) -> dict:
        """Get current WAF status.

        Returns:
            Status report dictionary.
        """
        state = self._lifecycle.load_state()
        return self._lifecycle.get_status_report(state)

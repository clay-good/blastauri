"""AI-assisted code review for upgrade impact analysis."""

import asyncio
import json
import shutil
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from blastauri.core.models import (
    ImpactedLocation,
    UpgradeImpact,
)


class AIProvider(str, Enum):
    """Supported AI providers."""

    CLAUDE = "claude"
    AUGMENT = "augment"
    NONE = "none"


@dataclass
class AIReviewResult:
    """Result from AI review."""

    summary: str
    confidence: float  # 0.0 to 1.0
    recommendations: list[str] = field(default_factory=list)
    additional_concerns: list[str] = field(default_factory=list)
    suggested_fixes: dict[str, str] = field(default_factory=dict)  # file_path -> fix
    raw_response: str | None = None


class BaseAIReviewer(ABC):
    """Base class for AI reviewers."""

    @abstractmethod
    async def review_upgrade(
        self,
        upgrade: UpgradeImpact,
        repository_path: Path,
    ) -> AIReviewResult:
        """Review an upgrade impact using AI.

        Args:
            upgrade: Upgrade impact analysis.
            repository_path: Path to the repository.

        Returns:
            AI review result.
        """
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """Check if this AI provider is available.

        Returns:
            True if available.
        """
        pass

    def _format_upgrade_context(
        self,
        upgrade: UpgradeImpact,
    ) -> str:
        """Format upgrade information for AI prompt.

        Args:
            upgrade: Upgrade impact analysis.

        Returns:
            Formatted context string.
        """
        parts = [
            "# Dependency Upgrade Analysis",
            "",
            f"## Package: {upgrade.dependency_name}",
            f"- Ecosystem: {upgrade.ecosystem.value}",
            f"- Version change: {upgrade.from_version} -> {upgrade.to_version}",
            f"- Major upgrade: {'Yes' if upgrade.is_major_upgrade else 'No'}",
            f"- Risk score: {upgrade.risk_score}/100 ({upgrade.severity.value})",
            "",
        ]

        if upgrade.breaking_changes:
            parts.append("## Breaking Changes")
            for i, change in enumerate(upgrade.breaking_changes, 1):
                parts.append(f"{i}. **{change.change_type.value}**: {change.description}")
                if change.old_api:
                    parts.append(f"   - Old: `{change.old_api}`")
                if change.new_api:
                    parts.append(f"   - New: `{change.new_api}`")
            parts.append("")

        if upgrade.impacted_locations:
            parts.append("## Impacted Code Locations")
            # Group by file
            by_file: dict[str, list[ImpactedLocation]] = {}
            for loc in upgrade.impacted_locations:
                by_file.setdefault(loc.location.file_path, []).append(loc)

            for file_path, locations in by_file.items():
                parts.append(f"### {file_path}")
                for loc in locations[:5]:  # Limit to 5 per file
                    parts.append(f"- Line {loc.location.line_number}: `{loc.location.code_snippet}`")
                    parts.append(f"  Breaking change: {loc.breaking_change.description[:50]}...")
                if len(locations) > 5:
                    parts.append(f"  ... and {len(locations) - 5} more")
            parts.append("")

        if upgrade.cves_fixed:
            parts.append("## CVEs Fixed by This Upgrade")
            for cve in upgrade.cves_fixed:
                parts.append(f"- {cve.id} ({cve.severity.value}): {cve.description[:100]}...")
            parts.append("")

        return "\n".join(parts)

    def _format_review_prompt(
        self,
        upgrade: UpgradeImpact,
        code_snippets: dict[str, str],
    ) -> str:
        """Format the review prompt for AI.

        Args:
            upgrade: Upgrade impact analysis.
            code_snippets: Relevant code snippets by file path.

        Returns:
            Formatted prompt.
        """
        context = self._format_upgrade_context(upgrade)

        code_section = ""
        if code_snippets:
            code_section = "\n## Relevant Code\n"
            for file_path, snippet in code_snippets.items():
                code_section += f"\n### {file_path}\n```\n{snippet}\n```\n"

        prompt = f"""{context}{code_section}
## Task

Please review this dependency upgrade and provide:

1. **Summary**: A brief assessment of the upgrade risk and impact.
2. **Recommendations**: Specific actions to take before/after the upgrade.
3. **Additional Concerns**: Any issues not captured by the automated analysis.
4. **Suggested Fixes**: Code changes needed for each impacted file.

Focus on:
- Whether the breaking changes will actually affect this codebase
- Any patterns that suggest the upgrade is safe or risky
- Security implications of upgrading or not upgrading

Respond in JSON format:
{{
    "summary": "...",
    "confidence": 0.0-1.0,
    "recommendations": ["...", "..."],
    "additional_concerns": ["...", "..."],
    "suggested_fixes": {{"file_path": "fix description"}}
}}
"""
        return prompt


class ClaudeReviewer(BaseAIReviewer):
    """AI reviewer using Claude CLI."""

    def __init__(self, model: str = "claude-3-5-sonnet-20241022"):
        """Initialize Claude reviewer.

        Args:
            model: Claude model to use.
        """
        self._model = model
        self._cli_path: str | None = None

    def is_available(self) -> bool:
        """Check if Claude CLI is available."""
        self._cli_path = shutil.which("claude")
        return self._cli_path is not None

    async def review_upgrade(
        self,
        upgrade: UpgradeImpact,
        repository_path: Path,
    ) -> AIReviewResult:
        """Review upgrade using Claude CLI."""
        if not self.is_available():
            return AIReviewResult(
                summary="Claude CLI not available",
                confidence=0.0,
            )

        # Get relevant code snippets
        code_snippets = self._get_code_snippets(upgrade, repository_path)

        # Format prompt
        prompt = self._format_review_prompt(upgrade, code_snippets)

        # Call Claude CLI
        try:
            result = await self._call_claude(prompt)
            return self._parse_response(result)
        except Exception as e:
            return AIReviewResult(
                summary=f"Error calling Claude: {e}",
                confidence=0.0,
                raw_response=str(e),
            )

    def _get_code_snippets(
        self,
        upgrade: UpgradeImpact,
        repository_path: Path,
    ) -> dict[str, str]:
        """Get relevant code snippets for review."""
        snippets: dict[str, str] = {}

        for loc in upgrade.impacted_locations[:10]:  # Limit to 10 locations
            file_path = Path(loc.location.file_path)

            if file_path.name in snippets:
                continue

            try:
                full_path = repository_path / file_path
                if full_path.exists():
                    content = full_path.read_text(encoding="utf-8")
                    lines = content.split("\n")

                    # Get context around the impacted line
                    start = max(0, loc.location.line_number - 5)
                    end = min(len(lines), loc.location.line_number + 10)
                    snippet = "\n".join(
                        f"{i}: {lines[i-1]}"
                        for i in range(start + 1, end + 1)
                    )
                    snippets[str(file_path)] = snippet

            except (OSError, UnicodeDecodeError):
                continue

        return snippets

    async def _call_claude(self, prompt: str) -> str:
        """Call Claude CLI with prompt."""
        process = await asyncio.create_subprocess_exec(
            self._cli_path or "claude",
            "--print",
            "--model", self._model,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        stdout, stderr = await process.communicate(prompt.encode())

        if process.returncode != 0:
            raise RuntimeError(f"Claude CLI failed: {stderr.decode()}")

        return stdout.decode()

    def _parse_response(self, response: str) -> AIReviewResult:
        """Parse Claude's response."""
        # Try to extract JSON from response
        try:
            # Find JSON block
            json_start = response.find("{")
            json_end = response.rfind("}") + 1

            if json_start >= 0 and json_end > json_start:
                json_str = response[json_start:json_end]
                data = json.loads(json_str)

                return AIReviewResult(
                    summary=data.get("summary", ""),
                    confidence=float(data.get("confidence", 0.5)),
                    recommendations=data.get("recommendations", []),
                    additional_concerns=data.get("additional_concerns", []),
                    suggested_fixes=data.get("suggested_fixes", {}),
                    raw_response=response,
                )

        except json.JSONDecodeError:
            pass

        # Fallback: use response as summary
        return AIReviewResult(
            summary=response[:500] if response else "No response",
            confidence=0.3,
            raw_response=response,
        )


class AugmentReviewer(BaseAIReviewer):
    """AI reviewer using Augment CLI."""

    def __init__(self):
        """Initialize Augment reviewer."""
        self._cli_path: str | None = None

    def is_available(self) -> bool:
        """Check if Augment CLI is available."""
        self._cli_path = shutil.which("augment")
        return self._cli_path is not None

    async def review_upgrade(
        self,
        upgrade: UpgradeImpact,
        repository_path: Path,
    ) -> AIReviewResult:
        """Review upgrade using Augment CLI."""
        if not self.is_available():
            return AIReviewResult(
                summary="Augment CLI not available",
                confidence=0.0,
            )

        # Format prompt
        prompt = self._format_review_prompt(upgrade, {})

        try:
            result = await self._call_augment(prompt, repository_path)
            return self._parse_response(result)
        except Exception as e:
            return AIReviewResult(
                summary=f"Error calling Augment: {e}",
                confidence=0.0,
                raw_response=str(e),
            )

    async def _call_augment(self, prompt: str, cwd: Path) -> str:
        """Call Augment CLI with prompt."""
        process = await asyncio.create_subprocess_exec(
            self._cli_path or "augment",
            "ask",
            prompt,
            cwd=str(cwd),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        stdout, stderr = await process.communicate()

        if process.returncode != 0:
            raise RuntimeError(f"Augment CLI failed: {stderr.decode()}")

        return stdout.decode()

    def _parse_response(self, response: str) -> AIReviewResult:
        """Parse Augment's response."""
        # Try to extract JSON
        try:
            json_start = response.find("{")
            json_end = response.rfind("}") + 1

            if json_start >= 0 and json_end > json_start:
                data = json.loads(response[json_start:json_end])
                return AIReviewResult(
                    summary=data.get("summary", ""),
                    confidence=float(data.get("confidence", 0.5)),
                    recommendations=data.get("recommendations", []),
                    additional_concerns=data.get("additional_concerns", []),
                    suggested_fixes=data.get("suggested_fixes", {}),
                    raw_response=response,
                )
        except json.JSONDecodeError:
            pass

        return AIReviewResult(
            summary=response[:500] if response else "No response",
            confidence=0.3,
            raw_response=response,
        )


class NoOpReviewer(BaseAIReviewer):
    """No-op reviewer when AI is disabled."""

    def is_available(self) -> bool:
        """Always available."""
        return True

    async def review_upgrade(
        self,
        upgrade: UpgradeImpact,
        repository_path: Path,
    ) -> AIReviewResult:
        """Return empty result."""
        return AIReviewResult(
            summary="AI review disabled",
            confidence=0.0,
        )


def get_ai_reviewer(provider: AIProvider) -> BaseAIReviewer:
    """Get an AI reviewer for the specified provider.

    Args:
        provider: AI provider to use.

    Returns:
        AI reviewer instance.
    """
    if provider == AIProvider.CLAUDE:
        return ClaudeReviewer()
    elif provider == AIProvider.AUGMENT:
        return AugmentReviewer()
    else:
        return NoOpReviewer()


async def ai_review_upgrade(
    upgrade: UpgradeImpact,
    repository_path: Path,
    provider: AIProvider = AIProvider.CLAUDE,
) -> AIReviewResult:
    """Convenience function to review an upgrade with AI.

    Args:
        upgrade: Upgrade impact analysis.
        repository_path: Path to repository.
        provider: AI provider to use.

    Returns:
        AI review result.
    """
    reviewer = get_ai_reviewer(provider)

    if not reviewer.is_available():
        # Try fallback providers
        fallback_providers = [AIProvider.CLAUDE, AIProvider.AUGMENT]
        for fallback in fallback_providers:
            if fallback != provider:
                fallback_reviewer = get_ai_reviewer(fallback)
                if fallback_reviewer.is_available():
                    return await fallback_reviewer.review_upgrade(upgrade, repository_path)

        # No AI available
        return AIReviewResult(
            summary="No AI provider available. Install claude or augment CLI.",
            confidence=0.0,
        )

    return await reviewer.review_upgrade(upgrade, repository_path)

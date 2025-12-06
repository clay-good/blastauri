"""Label manager for merge request severity labeling."""

from dataclasses import dataclass
from typing import Optional

from blastauri.core.models import Severity
from blastauri.git.gitlab_client import GitLabClient, ProjectLabel


@dataclass
class LabelDefinition:
    """Definition of a blastauri label."""

    name: str
    color: str
    description: str


# Security severity labels
SECURITY_LABELS = {
    Severity.CRITICAL: LabelDefinition(
        name="security:critical",
        color="#FF0000",
        description="Critical security vulnerability - immediate action required",
    ),
    Severity.HIGH: LabelDefinition(
        name="security:high",
        color="#FF6600",
        description="High severity security vulnerability",
    ),
    Severity.MEDIUM: LabelDefinition(
        name="security:medium",
        color="#FFCC00",
        description="Medium severity security vulnerability",
    ),
    Severity.LOW: LabelDefinition(
        name="security:low",
        color="#00CC00",
        description="Low severity security vulnerability",
    ),
}

# Blastauri analysis labels
BLASTAURI_LABELS = {
    "breaking": LabelDefinition(
        name="blastauri:breaking",
        color="#FF0000",
        description="Contains breaking changes that require code updates",
    ),
    "safe": LabelDefinition(
        name="blastauri:safe",
        color="#00CC00",
        description="Safe to merge - no breaking changes detected",
    ),
    "needs-review": LabelDefinition(
        name="blastauri:needs-review",
        color="#FFCC00",
        description="Requires manual review before merging",
    ),
    "waf-available": LabelDefinition(
        name="blastauri:waf-available",
        color="#0066FF",
        description="WAF rules available for mitigating vulnerabilities",
    ),
}

# All label definitions
ALL_LABELS = {
    **{f"security_{k.value}": v for k, v in SECURITY_LABELS.items()},
    **{f"blastauri_{k}": v for k, v in BLASTAURI_LABELS.items()},
}


class LabelManager:
    """Manages labels for merge requests."""

    def __init__(self, client: GitLabClient):
        """Initialize the label manager.

        Args:
            client: GitLab client instance.
        """
        self._client = client

    def ensure_labels_exist(self, project_id: str | int) -> list[ProjectLabel]:
        """Ensure all blastauri labels exist in the project.

        Args:
            project_id: Project ID or path.

        Returns:
            List of all ensured labels.
        """
        labels: list[ProjectLabel] = []

        for label_def in ALL_LABELS.values():
            label = self._client.ensure_label_exists(
                project_id,
                label_def.name,
                label_def.color,
                label_def.description,
            )
            labels.append(label)

        return labels

    def apply_severity_label(
        self,
        project_id: str | int,
        mr_iid: int,
        severity: Severity,
    ) -> None:
        """Apply appropriate severity label to an MR.

        Args:
            project_id: Project ID or path.
            mr_iid: Merge request IID.
            severity: Severity level.
        """
        # Remove any existing security labels
        self.remove_security_labels(project_id, mr_iid)

        # Apply new label if severity has a label
        label_def = SECURITY_LABELS.get(severity)
        if label_def:
            self._client.ensure_label_exists(
                project_id,
                label_def.name,
                label_def.color,
                label_def.description,
            )
            self._client.add_mr_labels(project_id, mr_iid, [label_def.name])

    def apply_analysis_labels(
        self,
        project_id: str | int,
        mr_iid: int,
        has_breaking_changes: bool,
        needs_review: bool,
        has_waf_available: bool,
    ) -> None:
        """Apply analysis result labels to an MR.

        Args:
            project_id: Project ID or path.
            mr_iid: Merge request IID.
            has_breaking_changes: Whether breaking changes were detected.
            needs_review: Whether manual review is needed.
            has_waf_available: Whether WAF rules are available.
        """
        # Remove existing blastauri labels
        self.remove_blastauri_labels(project_id, mr_iid)

        labels_to_add: list[str] = []

        # Ensure labels exist and determine which to apply
        if has_breaking_changes:
            label = BLASTAURI_LABELS["breaking"]
            self._client.ensure_label_exists(
                project_id, label.name, label.color, label.description
            )
            labels_to_add.append(label.name)
        elif not needs_review:
            label = BLASTAURI_LABELS["safe"]
            self._client.ensure_label_exists(
                project_id, label.name, label.color, label.description
            )
            labels_to_add.append(label.name)

        if needs_review:
            label = BLASTAURI_LABELS["needs-review"]
            self._client.ensure_label_exists(
                project_id, label.name, label.color, label.description
            )
            labels_to_add.append(label.name)

        if has_waf_available:
            label = BLASTAURI_LABELS["waf-available"]
            self._client.ensure_label_exists(
                project_id, label.name, label.color, label.description
            )
            labels_to_add.append(label.name)

        if labels_to_add:
            self._client.add_mr_labels(project_id, mr_iid, labels_to_add)

    def remove_security_labels(
        self,
        project_id: str | int,
        mr_iid: int,
    ) -> None:
        """Remove all security labels from an MR.

        Args:
            project_id: Project ID or path.
            mr_iid: Merge request IID.
        """
        labels_to_remove = [label.name for label in SECURITY_LABELS.values()]
        self._client.remove_mr_labels(project_id, mr_iid, labels_to_remove)

    def remove_blastauri_labels(
        self,
        project_id: str | int,
        mr_iid: int,
    ) -> None:
        """Remove all blastauri labels from an MR.

        Args:
            project_id: Project ID or path.
            mr_iid: Merge request IID.
        """
        labels_to_remove = [label.name for label in BLASTAURI_LABELS.values()]
        self._client.remove_mr_labels(project_id, mr_iid, labels_to_remove)

    def remove_all_blastauri_labels(
        self,
        project_id: str | int,
        mr_iid: int,
    ) -> None:
        """Remove all blastauri-related labels from an MR.

        Args:
            project_id: Project ID or path.
            mr_iid: Merge request IID.
        """
        self.remove_security_labels(project_id, mr_iid)
        self.remove_blastauri_labels(project_id, mr_iid)

    def get_severity_from_labels(
        self,
        labels: list[str],
    ) -> Optional[Severity]:
        """Determine severity from existing labels.

        Args:
            labels: List of label names.

        Returns:
            Severity if a security label is present.
        """
        for severity, label_def in SECURITY_LABELS.items():
            if label_def.name in labels:
                return severity
        return None

    def has_breaking_label(self, labels: list[str]) -> bool:
        """Check if MR has the breaking changes label.

        Args:
            labels: List of label names.

        Returns:
            True if breaking label is present.
        """
        return BLASTAURI_LABELS["breaking"].name in labels

    def has_safe_label(self, labels: list[str]) -> bool:
        """Check if MR has the safe label.

        Args:
            labels: List of label names.

        Returns:
            True if safe label is present.
        """
        return BLASTAURI_LABELS["safe"].name in labels

    def has_any_blastauri_label(self, labels: list[str]) -> bool:
        """Check if MR has any blastauri label.

        Args:
            labels: List of label names.

        Returns:
            True if any blastauri label is present.
        """
        blastauri_label_names = {label.name for label in BLASTAURI_LABELS.values()}
        security_label_names = {label.name for label in SECURITY_LABELS.values()}
        all_names = blastauri_label_names | security_label_names

        return bool(set(labels) & all_names)


def determine_labels_for_analysis(
    severity: Severity,
    breaking_changes_count: int,
    cves_fixed_count: int,
    waf_mitigatable_count: int,
) -> tuple[list[str], list[str]]:
    """Determine which labels to add/remove based on analysis.

    Args:
        severity: Overall severity.
        breaking_changes_count: Number of breaking changes.
        cves_fixed_count: Number of CVEs fixed.
        waf_mitigatable_count: Number of CVEs with WAF mitigation.

    Returns:
        Tuple of (labels_to_add, labels_to_remove).
    """
    add: list[str] = []
    remove: list[str] = []

    # Security label based on severity
    for sev, label_def in SECURITY_LABELS.items():
        if sev == severity:
            add.append(label_def.name)
        else:
            remove.append(label_def.name)

    # Breaking/safe labels
    if breaking_changes_count > 0:
        add.append(BLASTAURI_LABELS["breaking"].name)
        remove.append(BLASTAURI_LABELS["safe"].name)
    else:
        add.append(BLASTAURI_LABELS["safe"].name)
        remove.append(BLASTAURI_LABELS["breaking"].name)

    # Needs review for high severity or many breaking changes
    if severity in (Severity.CRITICAL, Severity.HIGH) or breaking_changes_count > 5:
        add.append(BLASTAURI_LABELS["needs-review"].name)
    else:
        remove.append(BLASTAURI_LABELS["needs-review"].name)

    # WAF available
    if waf_mitigatable_count > 0:
        add.append(BLASTAURI_LABELS["waf-available"].name)
    else:
        remove.append(BLASTAURI_LABELS["waf-available"].name)

    return add, remove

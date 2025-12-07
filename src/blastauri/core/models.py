"""Core data models for blastauri."""

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


class Ecosystem(str, Enum):
    """Supported package ecosystems."""

    NPM = "npm"
    PYPI = "pypi"
    GO = "go"
    RUBYGEMS = "rubygems"
    MAVEN = "maven"
    CARGO = "cargo"
    COMPOSER = "composer"


class Severity(str, Enum):
    """Vulnerability and impact severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"
    UNKNOWN = "unknown"


class BreakingChangeType(str, Enum):
    """Types of breaking changes that can occur in dependency upgrades."""

    REMOVED_FUNCTION = "removed_function"
    REMOVED_CLASS = "removed_class"
    REMOVED_MODULE = "removed_module"
    CHANGED_SIGNATURE = "changed_signature"
    RENAMED_EXPORT = "renamed_export"
    CHANGED_DEFAULT = "changed_default"
    CHANGED_BEHAVIOR = "changed_behavior"
    DEPRECATED = "deprecated"
    MAJOR_VERSION = "major_version"


class Dependency(BaseModel):
    """A single dependency parsed from a lockfile."""

    name: str = Field(..., description="Package name")
    version: str = Field(..., description="Package version")
    ecosystem: Ecosystem = Field(..., description="Package ecosystem")
    location: str = Field(..., description="Path to the lockfile containing this dependency")
    is_dev: bool = Field(default=False, description="Whether this is a development dependency")
    is_direct: bool = Field(default=True, description="Whether this is a direct dependency")
    parent: str | None = Field(default=None, description="Parent package if transitive")


class ScanResult(BaseModel):
    """Result of scanning a repository for dependencies."""

    dependencies: list[Dependency] = Field(default_factory=list)
    lockfiles_scanned: list[str] = Field(default_factory=list)
    scan_timestamp: datetime = Field(default_factory=datetime.utcnow)
    errors: list[str] = Field(default_factory=list)
    repository_path: str = Field(..., description="Path to the scanned repository")


class AffectedPackage(BaseModel):
    """Package affected by a CVE."""

    ecosystem: Ecosystem
    name: str
    version_start: str | None = None
    version_end: str | None = None
    fixed_version: str | None = None


class CVE(BaseModel):
    """Common Vulnerabilities and Exposures entry."""

    id: str = Field(..., description="CVE identifier (e.g., CVE-2021-44228)")
    description: str = Field(..., description="Vulnerability description")
    severity: Severity = Field(default=Severity.UNKNOWN)
    cvss_score: float | None = Field(default=None, ge=0.0, le=10.0)
    cvss_vector: str | None = None
    affected_packages: list[AffectedPackage] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    published_date: datetime | None = None
    modified_date: datetime | None = None
    source: str = Field(..., description="Source of CVE data (nvd, github, osv, gitlab)")
    is_waf_mitigatable: bool = Field(default=False)
    waf_pattern_id: str | None = None


class BreakingChange(BaseModel):
    """A breaking change detected in a dependency upgrade."""

    change_type: BreakingChangeType
    description: str
    old_api: str | None = None
    new_api: str | None = None
    migration_guide: str | None = None
    source: str = Field(..., description="Source of breaking change info (changelog, release notes)")


class UsageLocation(BaseModel):
    """Location where a dependency is used in the codebase."""

    file_path: str
    line_number: int = Field(..., ge=1)
    column: int = Field(..., ge=0)
    code_snippet: str
    usage_type: str = Field(..., description="Type of usage (import, call, attribute)")
    symbol: str = Field(..., description="The symbol being used")


class ImpactedLocation(BaseModel):
    """A usage location impacted by a breaking change."""

    location: UsageLocation
    breaking_change: BreakingChange
    confidence: float = Field(..., ge=0.0, le=1.0)
    suggested_fix: str | None = None


class UpgradeImpact(BaseModel):
    """Impact analysis for a single dependency upgrade."""

    dependency_name: str
    ecosystem: Ecosystem
    from_version: str
    to_version: str
    is_major_upgrade: bool = False
    breaking_changes: list[BreakingChange] = Field(default_factory=list)
    impacted_locations: list[ImpactedLocation] = Field(default_factory=list)
    cves_fixed: list[CVE] = Field(default_factory=list)
    risk_score: int = Field(default=0, ge=0, le=100)
    severity: Severity = Severity.LOW


class AnalysisReport(BaseModel):
    """Complete analysis report for a merge request."""

    merge_request_id: str
    repository: str
    analyzed_at: datetime = Field(default_factory=datetime.utcnow)
    upgrades: list[UpgradeImpact] = Field(default_factory=list)
    overall_risk_score: int = Field(default=0, ge=0, le=100)
    overall_severity: Severity = Severity.LOW
    summary: str = ""
    recommendations: list[str] = Field(default_factory=list)


class DependencyUpdate(BaseModel):
    """A dependency update parsed from an MR/PR."""

    ecosystem: Ecosystem
    name: str
    from_version: str
    to_version: str
    is_major: bool = False


class WafRule(BaseModel):
    """A WAF rule generated by blastauri."""

    rule_id: str
    cve_ids: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    mode: str = Field(default="log", description="Rule mode (log, block)")
    triggered_by: Dependency | None = None
    status: str = Field(default="active", description="Rule status (active, obsolete, promoted)")


class WafState(BaseModel):
    """WAF state tracking for a repository."""

    version: int = 1
    generated_at: datetime = Field(default_factory=datetime.utcnow)
    rules: list[WafRule] = Field(default_factory=list)


class CVEEntry(BaseModel):
    """A CVE entry for analysis results."""

    cve_id: str = Field(..., description="CVE identifier (e.g., CVE-2021-44228)")
    severity: Severity = Field(default=Severity.UNKNOWN)
    cvss_score: float | None = Field(default=None, ge=0.0, le=10.0)
    description: str = ""
    is_waf_mitigatable: bool = False


class CVEAnalysisResult(BaseModel):
    """Result of CVE analysis for a repository or package."""

    cves: list[CVEEntry] = Field(default_factory=list)
    total_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    waf_mitigatable_count: int = 0

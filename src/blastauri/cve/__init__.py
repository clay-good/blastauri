"""CVE intelligence module for vulnerability detection."""

from blastauri.cve.aggregator import CveAggregator
from blastauri.cve.cache import CveCache
from blastauri.cve.github_advisories import GitHubAdvisoriesClient
from blastauri.cve.gitlab_advisories import GitLabAdvisoriesClient
from blastauri.cve.nvd import NvdClient
from blastauri.cve.osv import OsvClient
from blastauri.cve.waf_patterns import (
    WafPattern,
    get_all_patterns,
    get_waf_pattern,
    get_waf_pattern_id,
    is_waf_mitigatable,
)

__all__ = [
    "CveAggregator",
    "CveCache",
    "GitHubAdvisoriesClient",
    "GitLabAdvisoriesClient",
    "NvdClient",
    "OsvClient",
    "WafPattern",
    "get_all_patterns",
    "get_waf_pattern",
    "get_waf_pattern_id",
    "is_waf_mitigatable",
]

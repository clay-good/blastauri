"""WAF-mitigatable CVE patterns and detection."""

import re
from collections.abc import Callable
from dataclasses import dataclass

from blastauri.core.models import CVE
from blastauri.utils.logging import get_logger

logger = get_logger(__name__)


@dataclass
class WafPattern:
    """Definition of a WAF-mitigatable vulnerability pattern."""

    id: str
    name: str
    description: str
    cve_ids: list[str]
    keywords: list[str]
    package_patterns: list[str]
    detection_function: Callable[[CVE], bool] | None = None


WAF_PATTERNS: dict[str, WafPattern] = {
    "log4j": WafPattern(
        id="log4j",
        name="Log4j JNDI Injection",
        description="Log4j remote code execution via JNDI lookup injection",
        cve_ids=[
            "CVE-2021-44228",
            "CVE-2021-45046",
            "CVE-2021-45105",
            "CVE-2021-44832",
        ],
        keywords=[
            "log4j",
            "jndi",
            "ldap injection",
            "log4shell",
        ],
        package_patterns=[
            r"log4j.*core",
            r"org\.apache\.logging\.log4j",
        ],
    ),
    "spring4shell": WafPattern(
        id="spring4shell",
        name="Spring4Shell Class Loader RCE",
        description="Spring Framework class loader manipulation vulnerability",
        cve_ids=[
            "CVE-2022-22965",
            "CVE-2022-22963",
        ],
        keywords=[
            "spring4shell",
            "springshell",
            "class.module.classLoader",
            "spring framework",
            "spring core",
        ],
        package_patterns=[
            r"spring.*core",
            r"spring.*beans",
            r"org\.springframework",
        ],
    ),
    "text4shell": WafPattern(
        id="text4shell",
        name="Text4Shell Apache Commons Text",
        description="Apache Commons Text string interpolation RCE",
        cve_ids=[
            "CVE-2022-42889",
        ],
        keywords=[
            "text4shell",
            "commons-text",
            "string interpolation",
            "stringsubstitutor",
        ],
        package_patterns=[
            r"commons-text",
            r"org\.apache\.commons\.text",
        ],
    ),
    "struts_ognl": WafPattern(
        id="struts_ognl",
        name="Apache Struts OGNL Injection",
        description="Apache Struts OGNL expression injection leading to RCE",
        cve_ids=[
            "CVE-2017-5638",
            "CVE-2018-11776",
            "CVE-2020-17530",
            "CVE-2021-31805",
        ],
        keywords=[
            "struts",
            "ognl",
            "content-type",
            "multipart",
        ],
        package_patterns=[
            r"struts.*core",
            r"org\.apache\.struts",
        ],
    ),
    "shellshock": WafPattern(
        id="shellshock",
        name="Shellshock Bash Vulnerability",
        description="Bash environment variable function definition RCE",
        cve_ids=[
            "CVE-2014-6271",
            "CVE-2014-7169",
        ],
        keywords=[
            "shellshock",
            "bash",
            "environment variable",
            "cgi",
        ],
        package_patterns=[
            r"^bash$",
        ],
    ),
    "jackson_deserialization": WafPattern(
        id="jackson_deserialization",
        name="Jackson Databind Deserialization",
        description="Jackson-databind unsafe deserialization vulnerabilities",
        cve_ids=[
            "CVE-2017-7525",
            "CVE-2019-12384",
            "CVE-2019-14379",
            "CVE-2020-36518",
        ],
        keywords=[
            "jackson",
            "databind",
            "deserialization",
            "polymorphic",
            "gadget chain",
        ],
        package_patterns=[
            r"jackson-databind",
            r"com\.fasterxml\.jackson",
        ],
    ),
    "prototype_pollution": WafPattern(
        id="prototype_pollution",
        name="JavaScript Prototype Pollution",
        description="Prototype pollution vulnerabilities in JavaScript libraries",
        cve_ids=[
            "CVE-2019-10744",
            "CVE-2020-8203",
            "CVE-2021-23337",
            "CVE-2022-46175",
        ],
        keywords=[
            "prototype pollution",
            "__proto__",
            "constructor.prototype",
            "lodash",
            "merge",
            "deep merge",
        ],
        package_patterns=[
            r"^lodash$",
            r"^lodash\.",
            r"^minimist$",
            r"^qs$",
            r"^json5$",
        ],
    ),
    "nextjs_middleware": WafPattern(
        id="nextjs_middleware",
        name="Next.js Middleware Auth Bypass",
        description="Next.js middleware authorization bypass vulnerability",
        cve_ids=[
            "CVE-2024-34350",
            "CVE-2024-34351",
        ],
        keywords=[
            "next.js",
            "nextjs",
            "middleware",
            "authorization bypass",
            "auth bypass",
        ],
        package_patterns=[
            r"^next$",
        ],
    ),
    "express_path_traversal": WafPattern(
        id="express_path_traversal",
        name="Express.js Path Traversal",
        description="Path traversal in Express.js static file serving",
        cve_ids=[
            "CVE-2017-14849",
            "CVE-2021-23017",
        ],
        keywords=[
            "express",
            "path traversal",
            "directory traversal",
            "static",
            "sendFile",
        ],
        package_patterns=[
            r"^express$",
            r"^serve-static$",
        ],
    ),
    "yaml_deserialization": WafPattern(
        id="yaml_deserialization",
        name="YAML Deserialization RCE",
        description="YAML parsing libraries with unsafe deserialization",
        cve_ids=[
            "CVE-2017-1000117",
            "CVE-2020-1747",
            "CVE-2021-21289",
        ],
        keywords=[
            "yaml",
            "deserialization",
            "unsafe_load",
            "snakeyaml",
            "pyyaml",
        ],
        package_patterns=[
            r"^pyyaml$",
            r"^snakeyaml$",
            r"^js-yaml$",
        ],
    ),
    "request_smuggling": WafPattern(
        id="request_smuggling",
        name="HTTP Request Smuggling",
        description="HTTP request smuggling vulnerabilities",
        cve_ids=[
            "CVE-2020-11724",
            "CVE-2023-25690",
        ],
        keywords=[
            "request smuggling",
            "desync",
            "transfer-encoding",
            "content-length",
            "cl.te",
            "te.cl",
        ],
        package_patterns=[],
    ),
    "sqli": WafPattern(
        id="sqli",
        name="SQL Injection",
        description="Generic SQL injection vulnerabilities",
        cve_ids=[],
        keywords=[
            "sql injection",
            "sqli",
            "sql query",
            "database injection",
            "query manipulation",
            "blind sql",
            "union-based",
            "time-based",
        ],
        package_patterns=[],
    ),
    "xss": WafPattern(
        id="xss",
        name="Cross-Site Scripting",
        description="Generic XSS vulnerabilities",
        cve_ids=[],
        keywords=[
            "cross-site scripting",
            "xss",
            "script injection",
            "html injection",
            "dom-based",
            "reflected xss",
            "stored xss",
            "template injection",
        ],
        package_patterns=[],
    ),
    "ssrf": WafPattern(
        id="ssrf",
        name="Server-Side Request Forgery",
        description="SSRF vulnerabilities allowing internal network access",
        cve_ids=[],
        keywords=[
            "ssrf",
            "server-side request forgery",
            "internal network",
            "metadata",
            "url fetch",
            "webhook",
        ],
        package_patterns=[],
    ),
    "xxe": WafPattern(
        id="xxe",
        name="XML External Entity Injection",
        description="XXE vulnerabilities in XML parsers",
        cve_ids=[],
        keywords=[
            "xxe",
            "xml external entity",
            "external entity",
            "dtd",
            "entity expansion",
        ],
        package_patterns=[],
    ),
    "command_injection": WafPattern(
        id="command_injection",
        name="Command Injection",
        description="OS command injection vulnerabilities",
        cve_ids=[],
        keywords=[
            "command injection",
            "os command",
            "shell injection",
            "exec",
            "system call",
            "subprocess",
        ],
        package_patterns=[],
    ),
}


def is_waf_mitigatable(cve: CVE) -> bool:
    """Check if a CVE can be mitigated by WAF rules.

    Args:
        cve: CVE to check.

    Returns:
        True if the CVE can be mitigated by WAF rules.
    """
    pattern_id = get_waf_pattern_id(cve)
    return pattern_id is not None


def get_waf_pattern_id(cve: CVE) -> str | None:
    """Get the WAF pattern ID for a CVE.

    Args:
        cve: CVE to check.

    Returns:
        Pattern ID or None if not WAF-mitigatable.
    """
    if cve.id in _get_all_cve_ids():
        for pattern_id, pattern in WAF_PATTERNS.items():
            if cve.id in pattern.cve_ids:
                return pattern_id

    description_lower = cve.description.lower()
    for pattern_id, pattern in WAF_PATTERNS.items():
        for keyword in pattern.keywords:
            if keyword.lower() in description_lower:
                return pattern_id

    for affected in cve.affected_packages:
        package_name = affected.name.lower()
        for pattern_id, pattern in WAF_PATTERNS.items():
            for pkg_pattern in pattern.package_patterns:
                if re.search(pkg_pattern, package_name, re.IGNORECASE):
                    if _matches_vulnerability_type(cve, pattern):
                        return pattern_id

    return None


def get_waf_pattern(pattern_id: str) -> WafPattern | None:
    """Get a WAF pattern by ID.

    Args:
        pattern_id: Pattern identifier.

    Returns:
        WafPattern or None if not found.
    """
    return WAF_PATTERNS.get(pattern_id)


def get_all_patterns() -> list[WafPattern]:
    """Get all defined WAF patterns.

    Returns:
        List of all WAF patterns.
    """
    return list(WAF_PATTERNS.values())


def _get_all_cve_ids() -> set[str]:
    """Get all CVE IDs from all patterns.

    Returns:
        Set of all CVE IDs.
    """
    cve_ids: set[str] = set()
    for pattern in WAF_PATTERNS.values():
        cve_ids.update(pattern.cve_ids)
    return cve_ids


def _matches_vulnerability_type(cve: CVE, pattern: WafPattern) -> bool:
    """Check if a CVE matches a vulnerability type pattern.

    Args:
        cve: CVE to check.
        pattern: Pattern to match against.

    Returns:
        True if the CVE matches the pattern's vulnerability type.
    """
    description_lower = cve.description.lower()

    # Generic attack type patterns - require keyword match
    generic_patterns = ("sqli", "xss", "ssrf", "xxe", "command_injection", "request_smuggling")
    if pattern.id in generic_patterns:
        for keyword in pattern.keywords:
            if keyword.lower() in description_lower:
                return True
        return False

    # Specific CVE patterns with known exploits
    if pattern.id == "log4j":
        return any(
            kw in description_lower
            for kw in ["jndi", "remote code", "rce", "injection", "lookup"]
        )

    if pattern.id == "spring4shell":
        return any(
            kw in description_lower
            for kw in ["classloader", "class loader", "remote code", "rce", "data binding"]
        )

    if pattern.id == "text4shell":
        return any(
            kw in description_lower
            for kw in ["interpolation", "lookup", "remote code", "rce", "script"]
        )

    if pattern.id == "struts_ognl":
        return any(
            kw in description_lower
            for kw in ["ognl", "expression", "remote code", "rce", "multipart"]
        )

    if pattern.id == "shellshock":
        return any(
            kw in description_lower
            for kw in ["function definition", "environment", "rce", "remote code"]
        )

    if pattern.id == "jackson_deserialization":
        return any(
            kw in description_lower
            for kw in ["deserialization", "polymorphic", "gadget", "remote code", "rce"]
        )

    if pattern.id == "prototype_pollution":
        return any(
            kw in description_lower
            for kw in ["prototype", "__proto__", "pollution", "merge", "deep"]
        )

    if pattern.id == "nextjs_middleware":
        return any(
            kw in description_lower
            for kw in ["middleware", "bypass", "authorization", "authentication"]
        )

    if pattern.id == "express_path_traversal":
        return any(
            kw in description_lower
            for kw in ["path traversal", "directory traversal", "static", "file"]
        )

    if pattern.id == "yaml_deserialization":
        return any(
            kw in description_lower
            for kw in ["deserialization", "unsafe", "load", "arbitrary code", "rce"]
        )

    return True

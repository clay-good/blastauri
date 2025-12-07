"""WAF rule templates for known CVEs and common attack patterns.

This module provides pre-defined WAF rule templates for:
- Known CVEs (Log4Shell, Spring4Shell, etc.)
- Common attack patterns (SQLi, XSS, RCE, etc.)
- OWASP Top 10 protections
"""

from dataclasses import dataclass, field
from enum import Enum

from blastauri.waf.providers.base import (
    WafRuleConfig,
    WafRuleDefinition,
    WafRuleMode,
    WafRuleStatement,
)


class AttackCategory(str, Enum):
    """Categories of attack patterns."""

    SQL_INJECTION = "sqli"
    CROSS_SITE_SCRIPTING = "xss"
    REMOTE_CODE_EXECUTION = "rce"
    PATH_TRAVERSAL = "path_traversal"
    LOG4J = "log4j"
    SPRING4SHELL = "spring4shell"
    COMMAND_INJECTION = "cmdi"
    SSRF = "ssrf"
    XXE = "xxe"
    LDAP_INJECTION = "ldapi"
    GENERIC = "generic"


@dataclass
class RuleTemplate:
    """A WAF rule template for a specific vulnerability or attack pattern."""

    template_id: str
    name: str
    description: str
    category: AttackCategory
    cve_ids: list[str] = field(default_factory=list)
    statements: list[WafRuleStatement] = field(default_factory=list)
    logic: str = "or"
    severity: str = "high"
    references: list[str] = field(default_factory=list)
    tags: dict[str, str] = field(default_factory=dict)

    def to_rule_definition(
        self,
        priority: int,
        mode: WafRuleMode = WafRuleMode.LOG,
        custom_tags: dict[str, str] = None,
    ) -> WafRuleDefinition:
        """Convert template to a rule definition.

        Args:
            priority: Rule priority.
            mode: Rule action mode.
            custom_tags: Additional tags to apply.

        Returns:
            WafRuleDefinition instance.
        """
        tags = dict(self.tags)
        tags["Category"] = self.category.value
        tags["Severity"] = self.severity
        if custom_tags:
            tags.update(custom_tags)

        config = WafRuleConfig(
            rule_id=self.template_id,
            name=self.name,
            description=self.description,
            priority=priority,
            mode=mode,
            cve_ids=self.cve_ids,
            pattern_id=self.template_id,
            tags=tags,
        )

        return WafRuleDefinition(
            config=config,
            statements=self.statements,
            logic=self.logic,
        )


class RuleTemplateRegistry:
    """Registry of WAF rule templates."""

    def __init__(self) -> None:
        """Initialize the registry with built-in templates."""
        self._templates: dict[str, RuleTemplate] = {}
        self._cve_mapping: dict[str, list[str]] = {}
        self._category_mapping: dict[AttackCategory, list[str]] = {}

        # Register built-in templates
        self._register_builtin_templates()

    def register(self, template: RuleTemplate) -> None:
        """Register a rule template.

        Args:
            template: Template to register.
        """
        self._templates[template.template_id] = template

        # Index by CVE
        for cve_id in template.cve_ids:
            if cve_id not in self._cve_mapping:
                self._cve_mapping[cve_id] = []
            self._cve_mapping[cve_id].append(template.template_id)

        # Index by category
        if template.category not in self._category_mapping:
            self._category_mapping[template.category] = []
        self._category_mapping[template.category].append(template.template_id)

    def get_template(self, template_id: str) -> RuleTemplate | None:
        """Get a template by ID.

        Args:
            template_id: Template identifier.

        Returns:
            RuleTemplate or None if not found.
        """
        return self._templates.get(template_id)

    def get_templates_for_cve(self, cve_id: str) -> list[RuleTemplate]:
        """Get all templates that protect against a CVE.

        Args:
            cve_id: CVE identifier.

        Returns:
            List of matching templates.
        """
        template_ids = self._cve_mapping.get(cve_id.upper(), [])
        return [self._templates[tid] for tid in template_ids]

    def get_templates_for_category(
        self,
        category: AttackCategory,
    ) -> list[RuleTemplate]:
        """Get all templates in a category.

        Args:
            category: Attack category.

        Returns:
            List of templates in category.
        """
        template_ids = self._category_mapping.get(category, [])
        return [self._templates[tid] for tid in template_ids]

    def get_all_templates(self) -> list[RuleTemplate]:
        """Get all registered templates.

        Returns:
            List of all templates.
        """
        return list(self._templates.values())

    def has_template_for_cve(self, cve_id: str) -> bool:
        """Check if a template exists for a CVE.

        Args:
            cve_id: CVE identifier.

        Returns:
            True if template exists.
        """
        return cve_id.upper() in self._cve_mapping

    def _register_builtin_templates(self) -> None:
        """Register all built-in rule templates."""
        # Log4Shell (CVE-2021-44228, CVE-2021-45046, CVE-2021-45105)
        self.register(
            RuleTemplate(
                template_id="log4shell-jndi",
                name="Log4Shell JNDI Injection",
                description="Blocks Log4Shell JNDI lookup exploitation attempts",
                category=AttackCategory.LOG4J,
                cve_ids=["CVE-2021-44228", "CVE-2021-45046", "CVE-2021-45105"],
                severity="critical",
                statements=[
                    WafRuleStatement(
                        field_type="uri",
                        match_type="regex",
                        patterns=[
                            r"\$\{jndi:",
                            r"\$\{j\$\{[^\}]*\}ndi:",
                            r"\$\{\$\{[^\}]*\}jndi:",
                        ],
                        transformations=["lowercase", "url_decode"],
                    ),
                    WafRuleStatement(
                        field_type="body",
                        match_type="regex",
                        patterns=[
                            r"\$\{jndi:",
                            r"\$\{j\$\{[^\}]*\}ndi:",
                        ],
                        transformations=["lowercase", "url_decode"],
                    ),
                    WafRuleStatement(
                        field_type="header",
                        field_name="User-Agent",
                        match_type="regex",
                        patterns=[r"\$\{jndi:"],
                        transformations=["lowercase", "url_decode"],
                    ),
                    WafRuleStatement(
                        field_type="header",
                        field_name="X-Forwarded-For",
                        match_type="regex",
                        patterns=[r"\$\{jndi:"],
                        transformations=["lowercase", "url_decode"],
                    ),
                ],
                logic="or",
                references=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
                    "https://logging.apache.org/log4j/2.x/security.html",
                ],
            )
        )

        # Spring4Shell (CVE-2022-22965)
        self.register(
            RuleTemplate(
                template_id="spring4shell",
                name="Spring4Shell RCE",
                description="Blocks Spring4Shell class loader manipulation attempts",
                category=AttackCategory.SPRING4SHELL,
                cve_ids=["CVE-2022-22965"],
                severity="critical",
                statements=[
                    WafRuleStatement(
                        field_type="query_string",
                        match_type="contains",
                        patterns=[
                            "class.module.classLoader",
                            "class%2Emodule%2EclassLoader",
                        ],
                        transformations=["url_decode"],
                    ),
                    WafRuleStatement(
                        field_type="body",
                        match_type="contains",
                        patterns=[
                            "class.module.classLoader",
                        ],
                        transformations=["url_decode"],
                    ),
                ],
                logic="or",
                references=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2022-22965",
                    "https://spring.io/blog/2022/03/31/spring-framework-rce-early-announcement",
                ],
            )
        )

        # Spring Cloud Function SpEL Injection (CVE-2022-22963)
        self.register(
            RuleTemplate(
                template_id="spring-cloud-spel",
                name="Spring Cloud Function SpEL Injection",
                description="Blocks Spring Cloud Function SpEL injection via routing header",
                category=AttackCategory.REMOTE_CODE_EXECUTION,
                cve_ids=["CVE-2022-22963"],
                severity="critical",
                statements=[
                    WafRuleStatement(
                        field_type="header",
                        field_name="spring.cloud.function.routing-expression",
                        match_type="regex",
                        patterns=[
                            r"T\s*\(",
                            r"Runtime",
                            r"ProcessBuilder",
                            r"exec\s*\(",
                        ],
                        transformations=["lowercase"],
                    ),
                ],
                logic="or",
                references=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2022-22963",
                ],
            )
        )

        # SQL Injection patterns
        self.register(
            RuleTemplate(
                template_id="sqli-common",
                name="SQL Injection Common Patterns",
                description="Blocks common SQL injection attack patterns",
                category=AttackCategory.SQL_INJECTION,
                cve_ids=[],
                severity="high",
                statements=[
                    WafRuleStatement(
                        field_type="uri",
                        match_type="regex",
                        patterns=[
                            r"(?i)(\%27)|(\')|(\-\-)|(\%23)|(#)",
                            r"(?i)(union).*?(select)",
                            r"(?i)(select).*?(from)",
                            r"(?i)(insert).*?(into)",
                            r"(?i)(drop).*?(table|database)",
                        ],
                        transformations=["url_decode", "lowercase"],
                    ),
                    WafRuleStatement(
                        field_type="query_string",
                        match_type="regex",
                        patterns=[
                            r"(?i)(\%27)|(\')|(\-\-)|(\%23)|(#)",
                            r"(?i)(union).*?(select)",
                            r"(?i)(select).*?(from)",
                        ],
                        transformations=["url_decode", "lowercase"],
                    ),
                    WafRuleStatement(
                        field_type="body",
                        match_type="regex",
                        patterns=[
                            r"(?i)(union).*?(select)",
                            r"(?i)(select).*?(from)",
                        ],
                        transformations=["url_decode", "lowercase"],
                    ),
                ],
                logic="or",
                references=[
                    "https://owasp.org/www-community/attacks/SQL_Injection",
                ],
            )
        )

        # XSS patterns
        self.register(
            RuleTemplate(
                template_id="xss-common",
                name="Cross-Site Scripting Common Patterns",
                description="Blocks common XSS attack patterns",
                category=AttackCategory.CROSS_SITE_SCRIPTING,
                cve_ids=[],
                severity="high",
                statements=[
                    WafRuleStatement(
                        field_type="uri",
                        match_type="regex",
                        patterns=[
                            r"<script[^>]*>",
                            r"javascript:",
                            r"on\w+\s*=",
                            r"<iframe[^>]*>",
                            r"<object[^>]*>",
                        ],
                        transformations=["url_decode", "html_entity_decode", "lowercase"],
                    ),
                    WafRuleStatement(
                        field_type="query_string",
                        match_type="regex",
                        patterns=[
                            r"<script[^>]*>",
                            r"javascript:",
                            r"on\w+\s*=",
                        ],
                        transformations=["url_decode", "html_entity_decode", "lowercase"],
                    ),
                    WafRuleStatement(
                        field_type="body",
                        match_type="regex",
                        patterns=[
                            r"<script[^>]*>",
                            r"javascript:",
                        ],
                        transformations=["url_decode", "html_entity_decode", "lowercase"],
                    ),
                ],
                logic="or",
                references=[
                    "https://owasp.org/www-community/attacks/xss/",
                ],
            )
        )

        # Path Traversal
        self.register(
            RuleTemplate(
                template_id="path-traversal",
                name="Path Traversal Attack",
                description="Blocks directory traversal attempts",
                category=AttackCategory.PATH_TRAVERSAL,
                cve_ids=[],
                severity="high",
                statements=[
                    WafRuleStatement(
                        field_type="uri",
                        match_type="regex",
                        patterns=[
                            r"\.\./",
                            r"\.\.\\",
                            r"%2e%2e%2f",
                            r"%2e%2e/",
                            r"\.%2e/",
                            r"%2e\./",
                        ],
                        transformations=["url_decode", "lowercase"],
                    ),
                    WafRuleStatement(
                        field_type="query_string",
                        match_type="regex",
                        patterns=[
                            r"\.\./",
                            r"\.\.\\",
                        ],
                        transformations=["url_decode", "lowercase"],
                    ),
                ],
                logic="or",
                references=[
                    "https://owasp.org/www-community/attacks/Path_Traversal",
                ],
            )
        )

        # Command Injection
        self.register(
            RuleTemplate(
                template_id="cmdi-common",
                name="Command Injection Common Patterns",
                description="Blocks common OS command injection patterns",
                category=AttackCategory.COMMAND_INJECTION,
                cve_ids=[],
                severity="critical",
                statements=[
                    WafRuleStatement(
                        field_type="uri",
                        match_type="regex",
                        patterns=[
                            r";\s*\w+",
                            r"\|\s*\w+",
                            r"`[^`]+`",
                            r"\$\([^\)]+\)",
                        ],
                        transformations=["url_decode"],
                    ),
                    WafRuleStatement(
                        field_type="query_string",
                        match_type="regex",
                        patterns=[
                            r";\s*\w+",
                            r"\|\s*\w+",
                            r"`[^`]+`",
                            r"\$\([^\)]+\)",
                        ],
                        transformations=["url_decode"],
                    ),
                    WafRuleStatement(
                        field_type="body",
                        match_type="regex",
                        patterns=[
                            r";\s*(cat|ls|id|whoami|wget|curl|nc|bash|sh|python|perl|ruby)",
                            r"\|\s*(cat|ls|id|whoami|wget|curl|nc|bash|sh|python|perl|ruby)",
                        ],
                        transformations=["url_decode", "lowercase"],
                    ),
                ],
                logic="or",
                references=[
                    "https://owasp.org/www-community/attacks/Command_Injection",
                ],
            )
        )

        # SSRF patterns
        self.register(
            RuleTemplate(
                template_id="ssrf-common",
                name="Server-Side Request Forgery",
                description="Blocks common SSRF attack patterns",
                category=AttackCategory.SSRF,
                cve_ids=[],
                severity="high",
                statements=[
                    WafRuleStatement(
                        field_type="query_string",
                        match_type="regex",
                        patterns=[
                            r"(localhost|127\.0\.0\.1|0\.0\.0\.0|169\.254\.\d+\.\d+)",
                            r"(10\.\d+\.\d+\.\d+)",
                            r"(172\.(1[6-9]|2[0-9]|3[0-1])\.\d+\.\d+)",
                            r"(192\.168\.\d+\.\d+)",
                            r"file://",
                            r"gopher://",
                            r"dict://",
                        ],
                        transformations=["url_decode", "lowercase"],
                    ),
                    WafRuleStatement(
                        field_type="body",
                        match_type="regex",
                        patterns=[
                            r"(localhost|127\.0\.0\.1)",
                            r"(169\.254\.\d+\.\d+)",
                            r"file://",
                        ],
                        transformations=["url_decode", "lowercase"],
                    ),
                ],
                logic="or",
                references=[
                    "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
                ],
            )
        )

        # XXE patterns
        self.register(
            RuleTemplate(
                template_id="xxe-common",
                name="XML External Entity Injection",
                description="Blocks XXE attack patterns",
                category=AttackCategory.XXE,
                cve_ids=[],
                severity="high",
                statements=[
                    WafRuleStatement(
                        field_type="body",
                        match_type="regex",
                        patterns=[
                            r"<!ENTITY",
                            r"<!DOCTYPE[^>]*\[",
                            r"SYSTEM\s+[\"']file:",
                            r"SYSTEM\s+[\"']http:",
                            r"PUBLIC\s+[\"'][^\"']*[\"']\s+[\"']file:",
                        ],
                        transformations=["lowercase"],
                    ),
                    WafRuleStatement(
                        field_type="header",
                        field_name="Content-Type",
                        match_type="contains",
                        patterns=["xml"],
                        transformations=["lowercase"],
                        negate=False,
                    ),
                ],
                logic="and",
                references=[
                    "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
                ],
            )
        )

        # LDAP Injection
        self.register(
            RuleTemplate(
                template_id="ldapi-common",
                name="LDAP Injection",
                description="Blocks LDAP injection patterns",
                category=AttackCategory.LDAP_INJECTION,
                cve_ids=[],
                severity="high",
                statements=[
                    WafRuleStatement(
                        field_type="query_string",
                        match_type="regex",
                        patterns=[
                            r"\(\|",
                            r"\(&",
                            r"\)\(",
                            r"\*\)",
                            r"\)\*",
                        ],
                        transformations=["url_decode"],
                    ),
                    WafRuleStatement(
                        field_type="body",
                        match_type="regex",
                        patterns=[
                            r"\(\|",
                            r"\(&",
                        ],
                        transformations=["url_decode"],
                    ),
                ],
                logic="or",
                references=[
                    "https://owasp.org/www-community/attacks/LDAP_Injection",
                ],
            )
        )

        # Apache Struts OGNL (CVE-2017-5638)
        self.register(
            RuleTemplate(
                template_id="struts-ognl",
                name="Apache Struts OGNL Injection",
                description="Blocks Apache Struts OGNL injection via Content-Type",
                category=AttackCategory.REMOTE_CODE_EXECUTION,
                cve_ids=["CVE-2017-5638"],
                severity="critical",
                statements=[
                    WafRuleStatement(
                        field_type="header",
                        field_name="Content-Type",
                        match_type="regex",
                        patterns=[
                            r"%\{",
                            r"\$\{",
                            r"#cmd",
                            r"#iswin",
                            r"ProcessBuilder",
                        ],
                        transformations=["url_decode", "lowercase"],
                    ),
                ],
                logic="or",
                references=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2017-5638",
                ],
            )
        )

        # Shellshock (CVE-2014-6271)
        self.register(
            RuleTemplate(
                template_id="shellshock",
                name="Shellshock Bash Vulnerability",
                description="Blocks Shellshock exploitation attempts",
                category=AttackCategory.COMMAND_INJECTION,
                cve_ids=["CVE-2014-6271", "CVE-2014-7169"],
                severity="critical",
                statements=[
                    WafRuleStatement(
                        field_type="header",
                        field_name="User-Agent",
                        match_type="regex",
                        patterns=[
                            r"\(\)\s*\{",
                            r"\(\)\s*\{[^}]*\}",
                        ],
                        transformations=[],
                    ),
                    WafRuleStatement(
                        field_type="header",
                        field_name="Referer",
                        match_type="regex",
                        patterns=[
                            r"\(\)\s*\{",
                        ],
                        transformations=[],
                    ),
                    WafRuleStatement(
                        field_type="header",
                        field_name="Cookie",
                        match_type="regex",
                        patterns=[
                            r"\(\)\s*\{",
                        ],
                        transformations=[],
                    ),
                ],
                logic="or",
                references=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2014-6271",
                ],
            )
        )

        # Text4Shell (CVE-2022-42889)
        self.register(
            RuleTemplate(
                template_id="text4shell",
                name="Text4Shell Apache Commons Text",
                description="Blocks Text4Shell string interpolation attacks",
                category=AttackCategory.REMOTE_CODE_EXECUTION,
                cve_ids=["CVE-2022-42889"],
                severity="critical",
                statements=[
                    WafRuleStatement(
                        field_type="uri",
                        match_type="regex",
                        patterns=[
                            r"\$\{script:",
                            r"\$\{dns:",
                            r"\$\{url:",
                        ],
                        transformations=["url_decode", "lowercase"],
                    ),
                    WafRuleStatement(
                        field_type="body",
                        match_type="regex",
                        patterns=[
                            r"\$\{script:",
                            r"\$\{dns:",
                            r"\$\{url:",
                        ],
                        transformations=["url_decode", "lowercase"],
                    ),
                    WafRuleStatement(
                        field_type="query_string",
                        match_type="regex",
                        patterns=[
                            r"\$\{script:",
                            r"\$\{dns:",
                            r"\$\{url:",
                        ],
                        transformations=["url_decode", "lowercase"],
                    ),
                ],
                logic="or",
                references=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2022-42889",
                ],
            )
        )

        # Prototype Pollution
        self.register(
            RuleTemplate(
                template_id="prototype-pollution",
                name="JavaScript Prototype Pollution",
                description="Blocks prototype pollution attack patterns",
                category=AttackCategory.GENERIC,
                cve_ids=["CVE-2019-10744", "CVE-2020-8203", "CVE-2021-23337"],
                severity="high",
                statements=[
                    WafRuleStatement(
                        field_type="body",
                        match_type="regex",
                        patterns=[
                            r"__proto__",
                            r"constructor\s*\[\s*['\"]prototype['\"]",
                            r"prototype\s*\[\s*['\"]constructor['\"]",
                        ],
                        transformations=["url_decode", "lowercase"],
                    ),
                    WafRuleStatement(
                        field_type="query_string",
                        match_type="regex",
                        patterns=[
                            r"__proto__",
                            r"constructor\[prototype\]",
                        ],
                        transformations=["url_decode", "lowercase"],
                    ),
                ],
                logic="or",
                references=[
                    "https://portswigger.net/daily-swig/prototype-pollution-the-dangerous-and-underrated-vulnerability-impacting-javascript-applications",
                ],
            )
        )

        # Jackson Deserialization
        self.register(
            RuleTemplate(
                template_id="jackson-deser",
                name="Jackson Databind Deserialization",
                description="Blocks Jackson polymorphic deserialization attacks",
                category=AttackCategory.REMOTE_CODE_EXECUTION,
                cve_ids=["CVE-2017-7525", "CVE-2019-12384", "CVE-2020-36518"],
                severity="critical",
                statements=[
                    WafRuleStatement(
                        field_type="body",
                        match_type="regex",
                        patterns=[
                            r"@type",
                            r"com\.sun\.rowset\.JdbcRowSetImpl",
                            r"com\.mchange\.v2\.c3p0",
                            r"org\.apache\.xalan",
                            r"com\.zaxxer\.hikari",
                            r"org\.hibernate\.jmx",
                        ],
                        transformations=["lowercase"],
                    ),
                ],
                logic="or",
                references=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2017-7525",
                ],
            )
        )

        # Additional Apache Struts OGNL patterns
        self.register(
            RuleTemplate(
                template_id="struts-ognl-extended",
                name="Apache Struts OGNL Extended",
                description="Extended protection against Struts OGNL injection",
                category=AttackCategory.REMOTE_CODE_EXECUTION,
                cve_ids=["CVE-2018-11776", "CVE-2020-17530", "CVE-2021-31805"],
                severity="critical",
                statements=[
                    WafRuleStatement(
                        field_type="uri",
                        match_type="regex",
                        patterns=[
                            r"%\{[^}]*#",
                            r"\$\{[^}]*getRuntime",
                            r"@ognl\.OgnlContext",
                        ],
                        transformations=["url_decode", "lowercase"],
                    ),
                    WafRuleStatement(
                        field_type="body",
                        match_type="regex",
                        patterns=[
                            r"%\{[^}]*#",
                            r"getRuntime\(\)\.exec",
                            r"ProcessBuilder",
                        ],
                        transformations=["url_decode", "lowercase"],
                    ),
                ],
                logic="or",
                references=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-31805",
                ],
            )
        )

        # YAML Deserialization
        self.register(
            RuleTemplate(
                template_id="yaml-deser",
                name="YAML Deserialization Attack",
                description="Blocks YAML deserialization exploitation attempts",
                category=AttackCategory.REMOTE_CODE_EXECUTION,
                cve_ids=["CVE-2020-1747", "CVE-2021-21289"],
                severity="critical",
                statements=[
                    WafRuleStatement(
                        field_type="body",
                        match_type="regex",
                        patterns=[
                            r"!!python/object",
                            r"!!python/module",
                            r"!ruby/object",
                            r"!ruby/hash",
                            r"!!javax\.script\.ScriptEngineManager",
                        ],
                        transformations=["lowercase"],
                    ),
                ],
                logic="or",
                references=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2020-1747",
                ],
            )
        )


# Global registry instance
_default_registry: RuleTemplateRegistry | None = None


def get_default_registry() -> RuleTemplateRegistry:
    """Get the default rule template registry.

    Returns:
        Default RuleTemplateRegistry instance.
    """
    global _default_registry
    if _default_registry is None:
        _default_registry = RuleTemplateRegistry()
    return _default_registry


def get_templates_for_cves(cve_ids: list[str]) -> list[RuleTemplate]:
    """Get all templates that protect against a list of CVEs.

    Args:
        cve_ids: List of CVE identifiers.

    Returns:
        List of matching templates (deduplicated).
    """
    registry = get_default_registry()
    templates: dict[str, RuleTemplate] = {}

    for cve_id in cve_ids:
        for template in registry.get_templates_for_cve(cve_id):
            templates[template.template_id] = template

    return list(templates.values())


def get_all_critical_templates() -> list[RuleTemplate]:
    """Get all critical severity templates.

    Returns:
        List of critical templates.
    """
    registry = get_default_registry()
    return [t for t in registry.get_all_templates() if t.severity == "critical"]


def get_owasp_top10_templates() -> list[RuleTemplate]:
    """Get templates covering OWASP Top 10 vulnerabilities.

    Returns:
        List of templates for OWASP Top 10.
    """
    registry = get_default_registry()
    owasp_categories = [
        AttackCategory.SQL_INJECTION,
        AttackCategory.CROSS_SITE_SCRIPTING,
        AttackCategory.COMMAND_INJECTION,
        AttackCategory.PATH_TRAVERSAL,
        AttackCategory.XXE,
        AttackCategory.SSRF,
    ]

    templates: dict[str, RuleTemplate] = {}
    for category in owasp_categories:
        for template in registry.get_templates_for_category(category):
            templates[template.template_id] = template

    return list(templates.values())

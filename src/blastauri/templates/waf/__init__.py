"""WAF Jinja2 templates for Terraform generation."""

from pathlib import Path

TEMPLATES_DIR = Path(__file__).parent


def get_template_path(name: str) -> Path:
    """Get the path to a WAF template.

    Args:
        name: Template name.

    Returns:
        Path to template file.
    """
    return TEMPLATES_DIR / name

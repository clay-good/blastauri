"""Comment templates for MR/PR analysis."""

from pathlib import Path

TEMPLATES_DIR = Path(__file__).parent


def get_template_path(name: str) -> Path:
    """Get the path to a comment template.

    Args:
        name: Template name.

    Returns:
        Path to template file.
    """
    return TEMPLATES_DIR / name

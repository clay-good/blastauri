"""Structured logging configuration for blastauri."""

import logging
import sys
from typing import Optional

from rich.console import Console
from rich.logging import RichHandler

_configured = False


def configure_logging(
    level: str = "INFO",
    format_string: Optional[str] = None,
) -> None:
    """Configure logging for the application.

    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL).
        format_string: Optional custom format string.
    """
    global _configured

    if _configured:
        return

    console = Console(stderr=True)

    handler = RichHandler(
        console=console,
        show_time=True,
        show_path=False,
        rich_tracebacks=True,
        tracebacks_show_locals=False,
        markup=True,
    )

    if format_string:
        handler.setFormatter(logging.Formatter(format_string))
    else:
        handler.setFormatter(logging.Formatter("%(message)s"))

    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.addHandler(handler)
    root_logger.setLevel(level.upper())

    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("gitlab").setLevel(logging.WARNING)
    logging.getLogger("github").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)

    _configured = True


def get_logger(name: str) -> logging.Logger:
    """Get a logger instance for the given module name.

    Args:
        name: Module name (typically __name__).

    Returns:
        Configured logger instance.
    """
    return logging.getLogger(name)


class LogContext:
    """Context manager for temporary log level changes."""

    def __init__(self, logger: logging.Logger, level: str) -> None:
        """Initialize the log context.

        Args:
            logger: Logger instance to modify.
            level: Temporary log level.
        """
        self.logger = logger
        self.new_level = getattr(logging, level.upper())
        self.original_level = logger.level

    def __enter__(self) -> "LogContext":
        """Enter the context and set new log level."""
        self.logger.setLevel(self.new_level)
        return self

    def __exit__(
        self,
        exc_type: Optional[type],
        exc_val: Optional[BaseException],
        exc_tb: Optional[object],
    ) -> None:
        """Exit the context and restore original log level."""
        self.logger.setLevel(self.original_level)


def silence_logger(name: str) -> None:
    """Silence a logger by setting its level to CRITICAL.

    Args:
        name: Logger name to silence.
    """
    logging.getLogger(name).setLevel(logging.CRITICAL)


def enable_debug_logging() -> None:
    """Enable debug logging for all blastauri loggers."""
    logging.getLogger("blastauri").setLevel(logging.DEBUG)


def log_to_file(
    filepath: str,
    level: str = "DEBUG",
    format_string: Optional[str] = None,
) -> logging.FileHandler:
    """Add a file handler to the root logger.

    Args:
        filepath: Path to the log file.
        level: Log level for the file handler.
        format_string: Optional custom format string.

    Returns:
        The configured FileHandler.
    """
    handler = logging.FileHandler(filepath)
    handler.setLevel(getattr(logging, level.upper()))

    if format_string:
        handler.setFormatter(logging.Formatter(format_string))
    else:
        handler.setFormatter(
            logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            )
        )

    logging.getLogger().addHandler(handler)
    return handler

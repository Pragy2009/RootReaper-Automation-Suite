"""
logger.py
Enterprise VAPT Logger with structured output
"""

import logging
from rich.console import Console
from rich.table import Table
from rich.logging import RichHandler

console = Console()

logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    handlers=[RichHandler(console=console, rich_tracebacks=True)]
)

logger = logging.getLogger("enterprise_vapt")


def log_info(msg):
    logger.info(msg)


def log_warning(msg):
    logger.warning(msg)


def log_error(msg):
    logger.error(msg)


def log_success(msg):
    console.print(f"[bold green][SUCCESS][/bold green] {msg}")


def log_step(msg):
    console.print(f"\n[bold cyan][STEP][/bold cyan] {msg}")


def log_section(title):
    console.print(f"\n[bold yellow]=== {title} ===[/bold yellow]")


def show_table(title, columns, data):
    """
    Generic table display
    """
    table = Table(title=title)

    for col in columns:
        table.add_column(col, style="cyan")

    for row in data:
        table.add_row(*[str(item) for item in row])

    console.print(table)

"""
Console utilities for formatted output.
"""
from datetime import datetime
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.theme import Theme

# Create a custom theme
custom_theme = Theme({
    "info": "cyan",
    "success": "green",
    "warning": "yellow",
    "error": "bold red",
    "debug": "dim blue",
    "header": "bold blue",
})

# Create a console with the custom theme
console = Console(theme=custom_theme)


def print_header(title: str) -> None:
    """Print a formatted section header"""
    console.print(Panel(title, style="header", expand=False))


def log(message: str, level: str = "info", timestamp: bool = True) -> None:
    """Log a message with appropriate formatting and optional timestamp"""
    timestamp_str = f"[{datetime.now().strftime('%H:%M:%S')}] " if timestamp else ""
    
    if level == "info":
        console.print(f"{timestamp_str}{message}", style="info")
    elif level == "success":
        console.print(f"{timestamp_str}✓ {message}", style="success")
    elif level == "warning":
        console.print(f"{timestamp_str}⚠ {message}", style="warning")
    elif level == "error":
        console.print(f"{timestamp_str}✗ {message}", style="error")
    elif level == "debug":
        console.print(f"{timestamp_str}🔍 {message}", style="debug")


def progress(iterable, description: Optional[str] = None):
    """Create a progress bar for iterating through items"""
    from rich.progress import Progress, TextColumn, BarColumn, TimeElapsedColumn
    
    with Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TextColumn("•"),
        TimeElapsedColumn(),
    ) as progress:
        task = progress.add_task(description or "Processing", total=len(iterable))
        for item in iterable:
            yield item
            progress.update(task, advance=1)
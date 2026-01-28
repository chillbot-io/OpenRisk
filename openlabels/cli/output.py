"""
OpenLabels CLI output utilities.

Provides rich-based output for user-facing CLI messages, tables, and progress bars.
Separates user output from operational logging.

Usage:
    from openlabels.cli.output import console, echo, error, warn, table, progress

    # User-facing messages
    echo("Scanning 100 files...")
    warn("Large file skipped")
    error("File not found")

    # Tables
    table(
        title="Scan Results",
        headers=["Path", "Score", "Tier"],
        rows=[("/data/file.txt", 85, "HIGH"), ...]
    )

    # Progress bars
    with progress("Scanning files", total=100) as p:
        for file in files:
            process(file)
            p.advance()
"""

import sys
from contextlib import contextmanager
from typing import List, Optional, Tuple, Any, Generator

from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.panel import Panel
from rich.text import Text


# Main console for stdout (user output)
console = Console()

# Error console for stderr
_err_console = Console(stderr=True)

# Global flag to disable progress bars (set via --no-progress)
_progress_enabled: bool = True


def set_progress_enabled(enabled: bool) -> None:
    """Enable or disable progress bars globally."""
    global _progress_enabled
    _progress_enabled = enabled


def is_progress_enabled() -> bool:
    """Check if progress bars are enabled."""
    return _progress_enabled and console.is_terminal


def echo(message: str, style: Optional[str] = None, nl: bool = True) -> None:
    """
    Print a message to the user.

    Args:
        message: The message to print
        style: Optional rich style (e.g., "bold", "green", "bold red")
        nl: Whether to add a newline (default: True)
    """
    console.print(message, style=style, end="\n" if nl else "")


def error(message: str) -> None:
    """
    Print an error message to stderr.

    Args:
        message: The error message
    """
    _err_console.print(f"[bold red]Error:[/bold red] {message}")


def warn(message: str) -> None:
    """
    Print a warning message.

    Args:
        message: The warning message
    """
    console.print(f"[yellow]Warning:[/yellow] {message}")


def success(message: str) -> None:
    """
    Print a success message.

    Args:
        message: The success message
    """
    console.print(f"[green]{message}[/green]")


def info(message: str) -> None:
    """
    Print an info message.

    Args:
        message: The info message
    """
    console.print(f"[blue]{message}[/blue]")


def dim(message: str) -> None:
    """
    Print a dimmed/secondary message.

    Args:
        message: The message
    """
    console.print(f"[dim]{message}[/dim]")


def table(
    headers: List[str],
    rows: List[Tuple[Any, ...]],
    title: Optional[str] = None,
    show_lines: bool = False,
) -> None:
    """
    Print a formatted table.

    Args:
        headers: Column headers
        rows: List of row tuples
        title: Optional table title
        show_lines: Show row separator lines
    """
    t = Table(title=title, show_lines=show_lines)

    for header in headers:
        t.add_column(header)

    for row in rows:
        t.add_row(*[str(cell) for cell in row])

    console.print(t)


def results_table(
    results: List[Any],
    columns: List[Tuple[str, str]],
    title: Optional[str] = None,
    max_rows: Optional[int] = None,
) -> None:
    """
    Print a table from result objects.

    Args:
        results: List of result objects with attributes
        columns: List of (header, attribute_name) tuples
        title: Optional table title
        max_rows: Maximum rows to display (shows "and N more" if exceeded)
    """
    t = Table(title=title)

    for header, _ in columns:
        t.add_column(header)

    display_results = results[:max_rows] if max_rows else results

    for result in display_results:
        row = []
        for _, attr in columns:
            value = getattr(result, attr, "")
            row.append(str(value))
        t.add_row(*row)

    console.print(t)

    if max_rows and len(results) > max_rows:
        dim(f"  ... and {len(results) - max_rows} more")


class ProgressContext:
    """Context wrapper for progress bar operations."""

    def __init__(self, progress: Progress, task_id: int):
        self._progress = progress
        self._task_id = task_id

    def advance(self, amount: int = 1) -> None:
        """Advance the progress bar."""
        self._progress.advance(self._task_id, amount)

    def update(self, completed: int) -> None:
        """Set the progress bar to a specific value."""
        self._progress.update(self._task_id, completed=completed)

    def set_description(self, description: str) -> None:
        """Update the progress bar description."""
        self._progress.update(self._task_id, description=description)


@contextmanager
def progress(
    description: str,
    total: Optional[int] = None,
    transient: bool = True,
) -> Generator[ProgressContext, None, None]:
    """
    Context manager for progress bars.

    Args:
        description: Description of the operation
        total: Total number of items (None for indeterminate spinner)
        transient: Remove progress bar when done (default: True)

    Yields:
        ProgressContext with advance() and update() methods

    Example:
        with progress("Scanning files", total=100) as p:
            for file in files:
                process(file)
                p.advance()
    """
    if not is_progress_enabled():
        # Progress disabled - yield a no-op context
        class NoOpProgress:
            def advance(self, amount: int = 1) -> None:
                pass

            def update(self, completed: int) -> None:
                pass

            def set_description(self, description: str) -> None:
                pass

        yield NoOpProgress()
        return

    if total is None:
        # Indeterminate progress (spinner)
        columns = [
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
        ]
    else:
        # Determinate progress (bar)
        columns = [
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
        ]

    with Progress(*columns, console=console, transient=transient) as p:
        task_id = p.add_task(description, total=total)
        yield ProgressContext(p, task_id)


def summary_box(title: str, items: List[Tuple[str, Any]]) -> None:
    """
    Print a summary box with key-value pairs.

    Args:
        title: Box title
        items: List of (label, value) tuples
    """
    content = "\n".join(f"[bold]{label}:[/bold] {value}" for label, value in items)
    console.print(Panel(content, title=title, border_style="blue"))


def divider(char: str = "─", style: str = "dim") -> None:
    """Print a horizontal divider line."""
    width = console.width or 60
    console.print(char * width, style=style)


def confirm(message: str, default: bool = False) -> bool:
    """
    Ask for user confirmation.

    Args:
        message: The confirmation prompt
        default: Default value if user just presses Enter

    Returns:
        True if user confirmed, False otherwise
    """
    suffix = "[Y/n]" if default else "[y/N]"
    response = console.input(f"{message} {suffix} ")

    if not response:
        return default

    return response.lower() in ("y", "yes")


def confirm_destructive(message: str, confirmation_word: str = "DELETE") -> bool:
    """
    Ask for confirmation of a destructive action.

    Requires user to type a specific word to confirm.

    Args:
        message: The confirmation prompt
        confirmation_word: Word the user must type to confirm

    Returns:
        True if user typed the confirmation word
    """
    console.print(f"[bold red]{message}[/bold red]")
    response = console.input(f"Type '{confirmation_word}' to confirm: ")
    return response == confirmation_word

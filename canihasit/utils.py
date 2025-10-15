# canihasit/utils.py
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.console import Console

console = Console()


def run_with_spinner(description: str, func, *args, **kwargs):
    """Run a function with a loading spinner

    Args:
        description: Text to display while running (without "...")
        func: Function to execute
        *args, **kwargs: Arguments to pass to func

    Returns:
        The result of func()
    """
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task(f"[yellow]{description}...", total=None)
        return func(*args, **kwargs)
    return None

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box
from .models import Severity

console = Console()

SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red on white",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.INFO: "dim",
}


def display_header():
    """Display the tool header"""
    text = Text.from_markup(
        """[bold cyan]wayup[/bold cyan]
[bold blue]Privilege Escalation Detector[/bold blue]
[gold1]Helping you find your way up to[/gold1] [bold][red]r[/red][dark_orange]o[/dark_orange][yellow]o[/yellow][green]t[/green][/bold]
[dim]by nconklindev[/dim] - [link]https://github.com/nconklindev/canihasit[/link]
        """,
        justify="center",
    )

    console.print(Panel.fit(text, subtitle="v0.1.0"))


# canihasit/output.py


def display_user_information(user_info):
    """Display user information as a table"""
    from rich.table import Table

    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Field", style="bold cyan")
    table.add_column("Value")

    table.add_row("User", f"{user_info.name} (uid={user_info.uid})")
    table.add_row("Primary Group", f"gid={user_info.gid}")
    table.add_row("Groups", ", ".join(user_info.groups))
    table.add_row("Home", user_info.home_dir)
    table.add_row("Shell", user_info.shell)

    console.print(table)
    console.print()

    if "sudo" in user_info.groups:
        console.print(
            f"[{SEVERITY_COLORS[Severity.MEDIUM]}]⚠ User has sudo group membership[/{SEVERITY_COLORS[Severity.MEDIUM]}]"
        )
        console.print()


def print_suid_sgid_info():
    """Print SUID/SGID informational header"""
    console.print("[dim]Reference: [link]https://gtfobins.github.io[/link][/dim]")


def display_sudo_permissions(permissions):
    """Display sudo permissions with color coding"""
    if not permissions:
        console.print("[dim]No sudo permissions found[/dim]")
        return

    # Known dangerous binaries
    SHELL_SPAWNERS = {
        "bash",
        "sh",
        "zsh",
        "fish",
        "dash",
        "vim",
        "vi",
        "nano",
        "emacs",
        "less",
        "more",
        "man",
        "python",
        "python3",
        "perl",
        "ruby",
        "node",
        "find",
        "awk",
        "sed",
        "nmap",
        "docker",
        "git",
    }

    for perm in permissions:
        # Special case: writable sudoers.d
        if perm.command == "WRITABLE_SUDOERS_D":
            color = SEVERITY_COLORS[Severity.CRITICAL]
            console.print(
                f"[{color}]CRITICAL[/{color}] /etc/sudoers.d/ is WRITABLE - direct privesc!"
            )
            continue

        # Extract binary from command
        binary = perm.command.split()[0].split("/")[-1] if perm.command.split() else ""

        # Determine severity
        severity = _determine_sudo_severity(perm, binary, SHELL_SPAWNERS)
        color = SEVERITY_COLORS[severity]

        # Build the output line
        nopasswd_str = "NOPASSWD: " if perm.nopasswd else ""
        prefix_str = (
            f"[{color}]{severity.value.upper()}[/{color}] "
            if severity != Severity.INFO
            else ""
        )

        console.print(f"{prefix_str}({perm.run_as}) {nopasswd_str}{perm.command}")


def _determine_sudo_severity(perm, binary: str, shell_spawners: set) -> Severity:
    """Determine the severity level for a sudo permission"""
    if perm.command == "ALL":
        return Severity.CRITICAL

    if perm.run_as in ("ALL", "root"):
        if binary in shell_spawners:
            return Severity.CRITICAL if perm.nopasswd else Severity.HIGH
        elif "*" in perm.command:
            return Severity.HIGH
        else:
            return Severity.MEDIUM

    return Severity.INFO


def display_os_information(os_name: str, os_version: str, node_name: str):
    """Display operating system information"""
    console.print(f"[bold cyan]Operating System:[/bold cyan] {os_name} {os_version}")
    console.print(f"[bold cyan]Node Name:[/bold cyan] {node_name}")


def display_suid_findings(suid_findings: list):
    """Display findings in a nice table"""
    if not suid_findings:
        console.print("[green]✓ No issues found![/green]")
        return

    table = Table(box=box.ROUNDED)
    table.add_column("Severity", style="bold")
    table.add_column("Issue", style="cyan")
    table.add_column("Path", style="dim")

    for finding in suid_findings:
        color = SEVERITY_COLORS[finding.severity]
        table.add_row(
            f"[{color}]{finding.severity.value.upper()}[/{color}]",
            finding.title,
            finding.path,
        )

    console.print(table)
    console.print(f"\n[yellow]Total findings:[/yellow] {len(suid_findings)}")

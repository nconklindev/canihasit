from rich.console import Console
from rich.rule import Rule
from .scanners import (
    SuidScanner,
    OperatingSystemScanner,
    SudoScanner,
    UserInformationScanner,
)
from .analyzers import SuidAnalyzer
from .output import (
    display_suid_findings,
    display_header,
    print_suid_sgid_info,
    display_sudo_permissions,
    display_user_information,
)
from .utils import run_with_spinner

console = Console()


def main():
    import sys
    try:
        display_header()
        console.print()

        # ===== User Information =====
        console.print(Rule("[bold]User Information[/bold]"))

        user_scanner = UserInformationScanner()
        user_info = run_with_spinner("Getting user information", user_scanner.scan)

        display_user_information(user_info)

        # ===== System Information =====
        console.print(Rule("[bold]System Information[/bold]"))

        os_scanner = OperatingSystemScanner()
        os_info = run_with_spinner("Getting OS information", os_scanner.scan)

        console.print(os_info)
        console.print()

        # ===== Sudo Configuration =====
        console.print(Rule("[bold]Sudo Configuration[/bold]"))
        console.print(
            "[dim]Reference: [link]https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-and-suid[/link][/dim]"
        )
        console.print()

        sudo_scanner = SudoScanner()
        sudo_perms = run_with_spinner("Checking sudo permissions", sudo_scanner.scan)

        display_sudo_permissions(sudo_perms)
        console.print()

        # ===== SUID/SGID Binaries =====
        console.print(Rule("[bold]SUID/SGID Binaries[/bold]"))
        print_suid_sgid_info()
        console.print()

        scanner = SuidScanner()
        binaries = run_with_spinner("Finding SUID/SGID binaries", scanner.scan)

        analyzer = SuidAnalyzer()
        findings = run_with_spinner("Analyzing for risks", analyzer.analyze, binaries)

        console.print()
        display_suid_findings(findings)
        console.print()
    except KeyboardInterrupt:
        # Graceful handling of Ctrl+C (SIGINT)
        console.print("\n[bold yellow]Interrupted by user (Ctrl+C). Exiting...[/bold yellow]")
        sys.exit(130)


if __name__ == "__main__":
    main()

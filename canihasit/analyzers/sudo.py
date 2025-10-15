# canihasit/analyzers/sudo.py
from ..models import SudoPermission, Finding, Severity


class SudoAnalyzer:
    """Analyzes sudo permissions for privilege escalation risks"""

    # Commands that can easily spawn shells
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

    def analyze(self, permissions: list[SudoPermission]) -> list[Finding]:
        """Analyze sudo permissions for risks"""
        findings = []

        for perm in permissions:
            if perm.command == "WRITABLE_SUDOERS_D":
                findings.append(
                    Finding(
                        title="Writable /etc/sudoers.d/ directory",
                        severity=Severity.CRITICAL,
                        path="/etc/sudoers.d/",
                    )
                )
                continue

            # Extract binary name from command
            binary = self._extract_binary(perm.command)

            # Check for dangerous configurations
            if perm.run_as in ("ALL", "root"):
                if binary in self.SHELL_SPAWNERS:
                    severity = Severity.CRITICAL if perm.nopasswd else Severity.HIGH

                    findings.append(
                        Finding(
                            title=f"Dangerous sudo permission: {binary}",
                            severity=severity,
                            path=perm.command,
                        )
                    )

                # Check for wildcards
                elif "*" in perm.command:
                    findings.append(
                        Finding(
                            title="Sudo wildcard detected",
                            severity=Severity.HIGH,
                            path=perm.command,
                        )
                    )

                # (ALL) ALL case
                elif perm.command == "ALL":
                    findings.append(
                        Finding(
                            title="Full sudo access granted",
                            severity=Severity.CRITICAL,
                            path="(ALL) ALL",
                        )
                    )

        return findings

    @staticmethod
    def _extract_binary(command: str) -> str:
        """Extract binary name from the full command path"""
        # Handle cases like "/usr/bin/vim" or "vim /path/to/file"
        parts = command.split()
        if parts:
            binary_path = parts[0]
            return binary_path.split("/")[-1]  # Get last part of path
        return ""

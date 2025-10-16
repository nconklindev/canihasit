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
        """Analyze sudo permissions for risks (micro-optimized, same behavior)"""
        findings: list[Finding] = []
        append = findings.append
        spawners = self.SHELL_SPAWNERS
        f = Finding
        sev = Severity
        crit = sev.CRITICAL
        high = sev.HIGH

        for perm in permissions:
            cmd = perm.command
            if cmd == "WRITABLE_SUDOERS_D":
                append(
                    f(
                        title="Writable /etc/sudoers.d/ directory",
                        severity=crit,
                        path="/etc/sudoers.d/",
                    )
                )
                continue

            # Extract binary name from command with minimal parsing
            parts = cmd.split()
            binary = parts[0].rpartition("/")[2] if parts else ""

            # Check for dangerous configurations
            if perm.run_as in ("ALL", "root"):
                if binary in spawners:
                    severity = crit if perm.nopasswd else high

                    append(
                        f(
                            title=f"Dangerous sudo permission: {binary}",
                            severity=severity,
                            path=cmd,
                        )
                    )

                # Check for wildcards
                elif "*" in cmd:
                    append(
                        f(
                            title="Sudo wildcard detected",
                            severity=high,
                            path=cmd,
                        )
                    )

                # (ALL) ALL case
                elif cmd == "ALL":
                    append(
                        f(
                            title="Full sudo access granted",
                            severity=crit,
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

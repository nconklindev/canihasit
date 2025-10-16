from ..models import SuidBinary, Finding, Severity


class SuidAnalyzer:
    """Analyzes SUID/SGID binaries for privilege escalation risks"""

    # Known risky SUID binaries
    def __init__(self):
        pass

    # TODO: Use GTFO Bins at some point
    RISKY_BINARIES = {
        "nmap",
        "vim",
        "find",
        "bash",
        "more",
        "less",
        "nano",
        "cp",
        "mv",
        "python",
        "perl",
        "ruby",
        "tar",
        "zip",
        "unzip",
        "awk",
        "sed",
    }

    def analyze(self, binaries: list[SuidBinary]) -> list[Finding]:
        """Analyze SUID/SGID binaries and create findings
        
        Optimized for reduced per-item overhead while preserving behavior.
        """
        findings: list[Finding] = []
        append = findings.append
        risky = self.RISKY_BINARIES
        High = Severity.HIGH
        Medium = Severity.MEDIUM
        F = Finding

        for binary in binaries:
            # Inline severity determination to avoid function call overhead
            severity = High if binary.name in risky else Medium
            bit_type = "SUID" if binary.is_suid else "SGID"

            append(
                F(
                    title=f"{bit_type} binary found",
                    severity=severity,
                    path=binary.path,
                )
            )

        return findings

    def _determine_severity(self, filename: str) -> Severity:
        """Determine risk level based on binary name"""
        if filename in self.RISKY_BINARIES:
            return Severity.HIGH
        return Severity.MEDIUM

# canihasit/analyzers/suid.py
from ..models import SuidBinary, Finding, Severity


class SuidAnalyzer:
    """Analyzes SUID/SGID binaries for privilege escalation risks"""

    # Known risky SUID binaries
    def __init__(self):
        pass

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
        """Analyze SUID/SGID binaries and create findings"""
        findings = []

        for binary in binaries:
            severity = self._determine_severity(binary.name)
            bit_type = "SUID" if binary.is_suid else "SGID"

            findings.append(
                Finding(
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

# canihasit/scanners/sudo.py
import subprocess
import os
from pathlib import Path
from ..models import SudoPermission


class SudoScanner:
    """Scans sudo configuration for privilege escalation risks"""

    def scan(self) -> list[SudoPermission]:
        """Check sudo permissions using multiple methods"""
        permissions = []

        # Method 1: Try sudo -l non-interactively first (most reliable)
        sudo_output = self._try_sudo_l_noninteractive()

        # Parse sudo -l output if we got any
        if sudo_output:
            permissions = self._parse_sudo_output(sudo_output)

        # Method 2: Read /etc/sudoers and /etc/sudoers.d/* directly
        sudoers_content = self._read_sudoers_files()
        if sudoers_content:
            permissions.extend(self._parse_sudoers_files(sudoers_content))

        return permissions

    def _try_sudo_l_noninteractive(self) -> str:
        """Try sudo -l without password prompt"""
        try:
            result = subprocess.run(
                ["sudo", "-n", "-l"], capture_output=True, text=True, timeout=2
            )

            if result.returncode == 0:
                return result.stdout

        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            pass

        return ""

    def _read_sudoers_files(self) -> list[tuple[str, str]]:
        """Read /etc/sudoers and /etc/sudoers.d/* files directly"""
        files_content = []

        # Try to read /etc/sudoers
        try:
            with open("/etc/sudoers", "r") as f:
                content = f.read()
                files_content.append(("/etc/sudoers", content))
        except (PermissionError, FileNotFoundError):
            pass

        # Check if /etc/sudoers.d/ is writable (privilege escalation!)
        sudoers_d = Path("/etc/sudoers.d")
        if sudoers_d.exists() and os.access(sudoers_d, os.W_OK):
            files_content.append(("/etc/sudoers.d/", "WRITABLE_DIRECTORY"))

        # Read files in /etc/sudoers.d/
        if sudoers_d.exists():
            try:
                for file_path in sudoers_d.iterdir():
                    if file_path.is_file():
                        try:
                            with open(file_path, "r") as f:
                                content = f.read()
                                files_content.append((str(file_path), content))
                        except PermissionError:
                            pass
            except PermissionError:
                pass

        return files_content

    def _parse_sudo_output(self, output: str) -> list[SudoPermission]:
        """Parse sudo -l output into structured data"""
        import re

        permissions = []
        current_user = None

        # Find the username line
        user_match = re.search(r"User (\w+) may run", output)
        if user_match:
            current_user = user_match.group(1)

        if not current_user:
            return []

        # Find permission lines
        lines = output.split("\n")

        for line in lines:
            line = line.strip()
            match = re.match(r"\(([^)]+)\)\s+(NOPASSWD:\s*)?(.+)", line)

            if match:
                run_as = match.group(1)
                nopasswd = match.group(2) is not None
                command = match.group(3).strip()

                permissions.append(
                    SudoPermission(
                        user=current_user,
                        run_as=run_as,
                        nopasswd=nopasswd,
                        command=command,
                    )
                )

        return permissions

    def _parse_sudoers_files(
        self, files_content: list[tuple[str, str]]
    ) -> list[SudoPermission]:
        """Parse sudoers file content"""
        import re

        permissions = []
        current_username = os.getenv("USER", "unknown")

        for file_path, content in files_content:
            # Check for writable directory
            if content == "WRITABLE_DIRECTORY":
                permissions.append(
                    SudoPermission(
                        user=current_username,
                        run_as="ALL",
                        nopasswd=True,
                        command="WRITABLE_SUDOERS_D",
                    )
                )
                continue

            # Parse sudoers syntax: username ALL=(ALL) NOPASSWD: /path/to/command
            lines = content.split("\n")
            for line in lines:
                line = line.strip()

                # Skip comments and empty lines
                if not line or line.startswith("#"):
                    continue

                # Match user entries
                # Format: username host=(runas) NOPASSWD: command
                match = re.match(r"(\w+)\s+\w+=\(([^)]+)\)\s+(NOPASSWD:\s*)?(.+)", line)

                if match:
                    user = match.group(1)
                    run_as = match.group(2)
                    nopasswd = match.group(3) is not None
                    command = match.group(4).strip()

                    # Only include rules for current user or ALL
                    if user == current_username or user == "ALL":
                        permissions.append(
                            SudoPermission(
                                user=user,
                                run_as=run_as,
                                nopasswd=nopasswd,
                                command=command,
                            )
                        )

        return permissions

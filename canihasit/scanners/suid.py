# canihasit/scanners/suid.py
import os
import stat
from pathlib import Path
from ..models import SuidBinary


class SuidScanner:
    """Scans for SUID/SGID binaries"""

    def scan(self) -> list[SuidBinary]:
        """Scan for SUID/SGID binaries recursively from root"""
        binaries = []
        root_dir = Path("/")

        for dirpath, dirnames, filenames in os.walk(root_dir):
            # Skip mnt while in WSL to avoid alerting on Windows dirs
            dirnames[:] = [d for d in dirnames if d not in {"mnt"}]

            for filename in filenames:
                file_path = Path(dirpath) / filename
                try:
                    if file_path.is_symlink():
                        continue

                    if file_path.is_file():
                        result = self._check_file(file_path)
                        if result:
                            binaries.append(result)

                except (PermissionError, OSError):
                    continue

        return binaries

    def _check_file(self, file_path: Path) -> SuidBinary | None:
        """Check if a file has SUID/SGID bit set"""
        try:
            file_stat = file_path.stat()
            mode = file_stat.st_mode

            has_suid = bool(mode & stat.S_ISUID)
            has_sgid = bool(mode & stat.S_ISGID)

            if has_suid or has_sgid:
                return SuidBinary(
                    path=str(file_path),
                    name=file_path.name,
                    is_suid=has_suid,
                    is_sgid=has_sgid,
                )

        except (PermissionError, OSError):
            pass

        return None

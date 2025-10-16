import os
import stat
from pathlib import Path
from ..models import SuidBinary


class SuidScanner:
    """Scans for SUID/SGID binaries"""

    def scan(self) -> list[SuidBinary]:
        """Scan for SUID/SGID binaries recursively from root, optimized to avoid slow/virtual mounts"""
        binaries = []
        root_dir = Path("/")

        # Stay on the same device by default (avoids scanning other mounts like /mnt, network FS)
        try:
            root_dev = os.stat(root_dir).st_dev
        except Exception:
            root_dev = None

        # Exclude virtual/heavy paths that cause massive slowdowns or permission noise
        excluded_prefixes = [
            Path("/proc"),
            Path("/sys"),
            Path("/dev"),
            Path("/run"),
            Path("/snap"),
            Path("/var/snap"),
            Path("/var/lib/docker"),
            Path("/var/lib/containers"),
            Path("/mnt"),  # Typically Windows mounts in WSL; also often network/external
        ]

        for dirpath, dirnames, filenames in os.walk(root_dir, topdown=True, followlinks=False):
            # Prune directories in-place for speed
            pruned = []
            for d in dirnames:
                full = Path(dirpath) / d
                try:
                    # Skip symlinked directories
                    if full.is_symlink():
                        continue

                    # Exclude known virtual/heavy prefixes
                    if any(full.is_relative_to(p) for p in excluded_prefixes):
                        continue

                    # Stay on the same device if detectable
                    if root_dev is not None:
                        try:
                            if full.stat(follow_symlinks=False).st_dev != root_dev:
                                continue
                        except (PermissionError, OSError):
                            # If we cannot stat, skip descending to avoid stalls
                            continue

                    pruned.append(d)
                except Exception:
                    # Be conservative: if anything odd, skip this path
                    continue
            dirnames[:] = pruned

            for filename in filenames:
                file_path = Path(dirpath) / filename
                try:
                    if file_path.is_symlink():
                        continue

                    result = self._check_file(file_path)
                    if result:
                        binaries.append(result)
                except (PermissionError, OSError):
                    continue

        return binaries

    def _check_file(self, file_path: Path) -> SuidBinary | None:
        """Check if a file has SUID/SGID bit set"""
        try:
            # Use lstat (no symlink following) to avoid unintended traversals
            file_stat = file_path.stat(follow_symlinks=False)
            mode = file_stat.st_mode

            # Only regular files are relevant for SUID/SGID
            if not stat.S_ISREG(mode):
                return None

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

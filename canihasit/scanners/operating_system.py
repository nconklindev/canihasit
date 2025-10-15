import os


class OperatingSystemScanner:
    """Scans for operating system information"""

    @staticmethod
    def _get_os_name() -> str:
        """Get the operating system name"""
        return os.uname().sysname

    @staticmethod
    def _get_nodename() -> str:
        """Get the node name"""
        return os.uname().nodename

    @staticmethod
    def _get_os_version() -> str:
        """Get the operating system version"""
        return os.uname().release

    def scan(self) -> str:
        """Get operating system information"""
        os_name = self._get_os_name()
        os_version = self._get_os_version()
        nodename = self._get_nodename()

        return f"[dim]System: {os_name} {os_version} | Host: {nodename}[/dim]"

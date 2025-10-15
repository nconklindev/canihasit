# canihasit/scanners/user_information.py
import os
import pwd
import grp

from ..models import UserInformation


class UserInformationScanner:
    """Scans for current user information"""

    def scan(self) -> UserInformation:
        """Get current user information"""
        # Get user info once
        uid = os.getuid()
        user_info = pwd.getpwuid(uid)

        user_name = user_info.pw_name
        user_id = uid
        user_group_id = user_info.pw_gid
        user_home_directory = user_info.pw_dir
        user_shell = user_info.pw_shell

        # Get all group memberships
        user_group_names = self._get_all_groups(user_name, user_group_id)

        return UserInformation(
            user_name,
            user_id,
            user_group_id,
            user_group_names,
            user_home_directory,
            user_shell,
        )

    @staticmethod
    def _get_all_groups(username: str, primary_gid: int) -> list[str]:
        """Get all groups the user belongs to (including primary)"""
        # Get primary group name
        try:
            primary_group = grp.getgrgid(primary_gid).gr_name
        except KeyError:
            primary_group = str(primary_gid)

        # Get supplementary groups
        supplementary_groups = [
            g.gr_name for g in grp.getgrall() if username in g.gr_mem
        ]

        # Combine, ensuring primary is first and no duplicates
        all_groups = [primary_group] + [
            g for g in supplementary_groups if g != primary_group
        ]

        return all_groups

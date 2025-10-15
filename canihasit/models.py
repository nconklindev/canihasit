# canihasit/models.py
from dataclasses import dataclass
from enum import Enum


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    title: str
    severity: Severity
    path: str


@dataclass
class SuidBinary:
    """Raw SUID/SGID binary data"""

    path: str
    name: str
    is_suid: bool
    is_sgid: bool


@dataclass
class SudoPermission:
    user: str
    run_as: str
    nopasswd: bool
    command: str


@dataclass
class UserInformation:
    name: str
    uid: int
    gid: int
    groups: list[str]
    home_dir: str
    shell: str

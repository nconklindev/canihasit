# canihasit 🔓

A privilege escalation detection tool for Linux systems, inspired by [linpeas](https://github.com/carlospolop/PEASS-ng). Built with Python and designed for security assessments and penetration testing.

## ⚠️ Disclaimer

**For educational and authorized security testing purposes only.**

Use of this tool on systems you do not own or have explicit written permission to test is illegal and unethical. The authors assume no liability and are not responsible for any misuse or damage caused by this program.

By using this tool, you agree that you have proper authorization to scan the target system and accept full responsibility for your actions.

## ✨ Features

- 🔍 **SUID/SGID Binary Detection** - Identifies binaries with elevated privileges
- 🛡️ **Sudo Configuration Analysis** - Checks sudo permissions and misconfigurations
- 💻 **System Information** - Gathers OS and environment details
- 👤 **User Information** - Enumerates current user privileges and group memberships
- 🎨 **Rich Terminal Output** - Color-coded severity levels for easy risk assessment
- ⚡ **Fast Scanning** - Efficient filesystem traversal with progress indicators

## 🚀 Installation

### Prerequisites

- Python 3.10 or higher
- Linux/WSL environment

### Install as a System-Wide CLI Tool (Recommended)

**Using pipx (Recommended):**
```bash
# Install pipx if you don't have it
sudo apt install pipx
# or
pip install --user pipx

# Ensure pipx is in PATH
pipx ensurepath

# Clone and install canihasit
git clone https://github.com/nconklindev/canihasit.git
cd canihasit
pipx install .

# Run from anywhere
cd ~
canihasit
```

**Using uv tool:**
```bash
# Install uv if you don't have it
curl -LsSf https://astral.sh/uv/install.sh | sh

# Clone and install canihasit
git clone https://github.com/nconklindev/canihasit.git
cd canihasit
uv tool install .

# Run from anywhere
cd ~
canihasit
```

**Quick install from GitHub (without cloning):**
```bash
# With pipx
pipx install git+https://github.com/nconklindev/canihasit.git

# Or with uv
uv tool install git+https://github.com/nconklindev/canihasit.git
```

### Development Installation

For contributing or local development:
```bash
# Clone the repository
git clone https://github.com/nconklindev/canihasit.git
cd canihasit

# Install uv if you don't have it installed
curl -LsSf https://astral.sh/uv/install.sh | sh

# Install dependencies
uv sync

# Run in development mode (from project directory)
uv run python -m canihasit

# Or install in editable mode
uv pip install -e .
canihasit
```

### Uninstall
```bash
# If installed with pipx
pipx uninstall canihasit

# If installed with uv tool
uv tool uninstall canihasit
```

## 📖 Usage
```bash
# Run the scanner (works from any directory after installation)
canihasit
```

### Example Output
```
╭───────────────────────────────────────────────────────────╮
│                         canihasit                         │
│               Privilege Escalation Detector               │
│ by nconklindev - https://github.com/nconklindev/canihasit │
│                                                           │
╰───────────────────────── v0.1.0 ──────────────────────────╯

━━━━━━━━━━━━━ System Information ━━━━━━━━━━━━━
System: Linux 5.15.153.1-microsoft-standard-WSL2 | Host: hostname

━━━━━━━━━━━━━ User Information ━━━━━━━━━━━━━
User: john_wick (uid=1000, gid=1000)
Home: /home/john_wick
Shell: /bin/bash
Groups: john_wick, adm, sudo, docker
⚠ User has sudo group membership

━━━━━━━━━━━━━ Sudo Configuration ━━━━━━━━━━━━━
Reference: https://book.hacktricks.wiki/...

CRITICAL (ALL) NOPASSWD: ALL
HIGH (root) NOPASSWD: /usr/bin/vim

━━━━━━━━━━━━━ SUID/SGID Binaries ━━━━━━━━━━━━━
Reference: https://gtfobins.github.io

Found 47 binaries

╭──────────┬───────────────────────┬─────────────────────╮
│ Severity │ Issue                 │ Path                │
├──────────┼───────────────────────┼─────────────────────┤
│ HIGH     │ SUID binary found     │ /usr/bin/sudo       │
│ MEDIUM   │ SUID binary found     │ /usr/bin/mount      │
╰──────────┴───────────────────────┴─────────────────────╯
```

## 🎯 Roadmap

- [ ] Kernel exploit detection
- [ ] Writable files and directories
- [ ] Cron job analysis
- [ ] Capabilities enumeration
- [ ] Docker/container escape checks
- [ ] Network service enumeration
- [ ] Password file analysis
- [ ] SSH key discovery
- [ ] JSON/HTML report output
- [ ] Custom scan profiles

## 🛠️ Development

### Setup Development Environment
```bash
# Clone and install dependencies
git clone https://github.com/nconklindev/canihasit.git
cd canihasit
uv sync

# Run in development mode
uv run python -m canihasit

# Format code with black
uv run black canihasit/

# Run tests (when available)
uv run pytest
```

### Adding a New Scanner

1. Create scanner in `canihasit/scanners/`
2. Create analyzer in `canihasit/analyzers/`
3. Add data model in `canihasit/models.py`
4. Create display function in `canihasit/output.py`
5. Integrate in `canihasit/cli.py`

## 📚 References

- [GTFOBins](https://gtfobins.github.io/) - Unix binaries that can be used for privilege escalation
- [HackTricks - Linux Privilege Escalation](https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/)
- [LinPEAS](https://github.com/carlospolop/PEASS-ng) - Linux Privilege Escalation Awesome Script

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Inspired by [LinPEAS](https://github.com/carlospolop/PEASS-ng) by Carlos Polop
- Built with [Rich](https://github.com/Textualize/rich) for beautiful terminal output
- Powered by [uv](https://github.com/astral-sh/uv) for fast Python packaging

## 📧 Contact

[@nconklindev](https://github.com/nconklindev)

Project Link: [https://github.com/nconklindev/canihasit](https://github.com/nconklindev/canihasit)

---

**Remember**: Always obtain proper authorization before running security tools on any system. 🔐
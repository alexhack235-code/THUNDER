# Contributing to THUNDER

Thank you for your interest in contributing to **THUNDER: Enterprise Network & Device Defender**!

## How to Contribute

### 1. Reporting Bugs
- Check existing issues to see if the problem has already been reported.
- For non-security bugs, open a GitHub Issue with full details:
  - Operating System & version (Windows 10/11, Ubuntu, Termux, etc.)
  - PowerShell version (`$PSVersionTable`) or Bash version (`bash --version`)
  - Steps to reproduce
  - Relevant logs from `logs/defender_events.log`

### 2. Code Contributions
- Fork the repository and create a feature branch (`git checkout -b feature/defense-layer`).
- Follow code conventions:
  - PowerShell scripts must run cleanly on PowerShell 5.1 and PowerShell 7+.
  - Bash scripts must use POSIX-compliant syntax compatible with Linux and Termux.
  - Rust code in `thunder-scanner` must pass `cargo check` and `cargo test` without warnings.
- Avoid introducing false positives that could disrupt legitimate developer workflows (e.g. killing development servers, tools, or compilers).

### 3. Testing Changes
- Test on both Windows (PowerShell) and Linux (Bash) if modifying cross-platform features.
- Test quarantine and shred operations on test files only (e.g. standard EICAR test string).

### 4. Pull Requests
- Keep PRs focused on a single feature or bug fix.
- Include a clear description of the problem solved.

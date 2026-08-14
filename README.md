# hb-updater

A Python utility for macOS to automate Homebrew updates, track package upgrades, and identify fixed security vulnerabilities (CVEs).

## Overview

`hb-updater` streamlines your Homebrew maintenance workflow by automating package updates and providing a detailed security summary at the end of the update process.

## Key Features

- **Automated Workflow**: Sequentially runs `brew update`, `brew upgrade`, and `brew cleanup`.
- **Pre-Upgrade Inspection**: Detects outdated formulae and casks prior to upgrading.
- **CVE & Security Advisory Lookup**: Queries the [OSV.dev](https://osv.dev) database to check for security vulnerabilities and CVE IDs fixed in the upgraded package versions.
- **Formatted Summary**: Prints a clear end-of-run summary of all updated packages (old vs. new version) and associated security advisories.

## How It Works

1. **Update Formulae**: Executes `brew update` to fetch the latest formula definitions.
2. **Detect Outdated Packages**: Captures outdated package information using `brew outdated --json`.
3. **Upgrade Packages**: Executes `brew upgrade` to install the latest versions.
4. **Cleanup**: Runs `brew cleanup` to remove cached downloads and old versions.
5. **Security Report**: Queries OSV.dev and prints a summary box showing package changes and security fixes.

## Usage

Run the script directly using Python 3:

```bash
python3 hbupdate.py
```

### Example Output

```text
============================================================
                HOMEBREW UPDATE SUMMARY
============================================================
Total Packages Updated: 2

• [FORMULA] go
  Version: 1.26.5 → 1.26.6
  CVEs / Advisories Fixed: CVE-2026-33818, CVE-2026-56864, CVE-2026-56865

• [FORMULA] python@3.14
  Version: 3.14.6 → 3.14.7
  CVEs / Advisories Fixed: None reported

============================================================
```

## Requirements

- macOS
- [Homebrew](https://brew.sh)
- Python 3.6+

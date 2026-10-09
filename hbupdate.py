#!/usr/bin/env python3

import json
import subprocess
import urllib.request
import urllib.parse

def run_command(cmd, capture_output=False):
    """Run a shell command and stream or return its output."""
    if capture_output:
        result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        return result.returncode, result.stdout
    else:
        process = subprocess.Popen(
            cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
        )
        for line in process.stdout:
            print(line, end="")
        process.wait()
        return process.returncode

def get_outdated_packages():
    """Retrieve list of outdated packages before running brew upgrade."""
    outdated = []
    code, output = run_command("brew outdated --json", capture_output=True)
    if code == 0 and output.strip():
        try:
            data = json.loads(output)
            formulae = data.get("formulae", [])
            for f in formulae:
                name = f.get("name")
                installed = f.get("installed_versions", [])
                current = f.get("current_version")
                old_ver = installed[0] if installed else "unknown"
                outdated.append({
                    "name": name,
                    "type": "formula",
                    "old_version": old_ver,
                    "new_version": current
                })
            
            casks = data.get("casks", [])
            for c in casks:
                name = c.get("name")
                installed = c.get("installed_versions", [])
                current = c.get("current_version")
                old_ver = installed[0] if installed else "unknown"
                outdated.append({
                    "name": name,
                    "type": "cask",
                    "old_version": old_ver,
                    "new_version": current
                })
        except Exception:
            pass
    return outdated

# Homebrew formula names do not match any OSV ecosystem directly: OSV has no
# populated "Homebrew" ecosystem, and a name-only query fuzzy-matches across
# unrelated ecosystems (e.g. "go" resolves to a Linux distro's package feed).
# We therefore map well-known formulae to the ecosystem where OSV actually has
# upstream advisory data, and query that with the installed version.
#
# Each value is (ecosystem, osv_package_name).
FORMULA_ECOSYSTEM_MAP = {
    # Go toolchain -> Go standard library advisories.
    "go": ("Go", "stdlib"),
    # Language runtimes -> their package indexes.
    "python": ("PyPI", "python"),
    "node": ("npm", "node"),
    # Common C/native libraries and tools covered by OSV's upstream data.
    "openssl": ("OSS-Fuzz", "openssl"),
    "curl": ("OSS-Fuzz", "curl"),
    "wget": ("OSS-Fuzz", "wget"),
    "git": ("OSS-Fuzz", "git"),
    "ffmpeg": ("OSS-Fuzz", "ffmpeg"),
    "sqlite": ("OSS-Fuzz", "sqlite3"),
    "libxml2": ("OSS-Fuzz", "libxml2"),
    "redis": ("OSS-Fuzz", "redis"),
}

# OSV mixes upstream advisories with per-distro package feeds. When we query by
# name those distro entries pollute the result with duplicate, distro-scoped
# IDs, so we drop any vuln whose affected ecosystem is one of these feeds.
_DISTRO_ECOSYSTEM_PREFIXES = (
    "Alpine", "Alpaquita", "Chainguard", "Debian", "Ubuntu", "Red Hat",
    "Rocky Linux", "AlmaLinux", "SUSE", "openSUSE", "Wolfi", "Mageia",
    "Photon OS", "GHC",
)


def resolve_ecosystem(pkg_name):
    """Map a Homebrew formula name to an (ecosystem, name) OSV query, or None.

    Returns None when we have no reliable mapping, so the caller can report
    "not covered" rather than a misleading "no CVEs".
    """
    base = pkg_name.split('@')[0].lower()

    if base in FORMULA_ECOSYSTEM_MAP:
        return FORMULA_ECOSYSTEM_MAP[base]

    # Heuristic fallbacks for versioned / conventionally-named formulae.
    if base.startswith("python"):
        return ("PyPI", "python")
    if base.startswith("node"):
        return ("npm", "node")
    if base.endswith("-rs"):
        return ("crates.io", base[:-3])

    return None


def _is_distro_vuln(vuln):
    """True if every affected package for this vuln is a distro-specific feed."""
    affected = vuln.get('affected', [])
    if not affected:
        return False
    for aff in affected:
        eco = aff.get('package', {}).get('ecosystem', '')
        if not any(eco.startswith(p) for p in _DISTRO_ECOSYSTEM_PREFIXES):
            return False  # at least one upstream/non-distro entry -> keep it
    return True


def fetch_cves_for_package(pkg_name, old_ver, new_ver):
    """Look up CVEs affecting the OLD version of a package.

    Returns (status, cve_list) where status is one of:
      "ok"          - lookup succeeded; cve_list holds the IDs (possibly empty)
      "uncovered"   - no OSV ecosystem mapping; cve_list is empty
      "error"       - the OSV request failed; cve_list is empty
    """
    resolved = resolve_ecosystem(pkg_name)
    if resolved is None:
        return ("uncovered", [])

    ecosystem, osv_name = resolved
    url = "https://api.osv.dev/v1/query"
    payload = {
        "package": {"ecosystem": ecosystem, "name": osv_name},
        "version": old_ver,
    }

    cves = []
    try:
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode('utf-8'),
            headers={'Content-Type': 'application/json', 'User-Agent': 'hb-updater/1.0'}
        )
        with urllib.request.urlopen(req, timeout=4) as response:
            res = json.loads(response.read().decode('utf-8'))
            for v in res.get('vulns', []):
                if _is_distro_vuln(v):
                    continue
                # Prefer a real CVE alias; fall back to the advisory ID only
                # when no CVE is associated (e.g. GHSA-/GO-only entries).
                cve_aliases = [a for a in v.get('aliases', []) if a.startswith('CVE-')]
                if cve_aliases:
                    cves.extend(cve_aliases)
                elif v.get('id'):
                    cves.append(v['id'])
    except Exception:
        return ("error", [])

    return ("ok", sorted(set(cves)))

def display_summary(updated_packages):
    """Display a clean summary of updated packages and fixed CVEs."""
    print("\n" + "=" * 60)
    print("                HOMEBREW UPDATE SUMMARY")
    print("=" * 60)
    
    if not updated_packages:
        print("No packages were updated.")
        print("=" * 60 + "\n")
        return

    print(f"Total Packages Updated: {len(updated_packages)}\n")
    
    for pkg in updated_packages:
        name = pkg["name"]
        old_v = pkg["old_version"]
        new_v = pkg["new_version"]
        pkg_type = pkg["type"]
        
        print(f"• [{pkg_type.upper()}] {name}")
        print(f"  Version: {old_v} → {new_v}")
        
        status, cves = fetch_cves_for_package(name, old_v, new_v)
        if status == "ok" and cves:
            print(f"  CVEs fixed: {', '.join(cves)}")
        elif status == "ok":
            print("  CVEs fixed: None reported")
        elif status == "uncovered":
            print("  CVE status: Not covered by OSV (no ecosystem mapping)")
        else:  # error
            print("  CVE status: Lookup failed (OSV unreachable)")
        print()
        
    print("=" * 60 + "\n")

def update_homebrew():
    print("Updating Homebrew...")
    if run_command("brew update") != 0:
        print("Failed to update Homebrew.")
        return

    print("\nChecking for outdated packages...")
    outdated_packages = get_outdated_packages()

    print("\nUpgrading installed packages...")
    if run_command("brew upgrade") != 0:
        print("Failed to upgrade packages.")
        return

    print("\nCleaning up old Homebrew files...")
    run_command("brew cleanup")

    print("\nHomebrew update complete!")
    
    # Print summary of updated packages and CVEs
    display_summary(outdated_packages)

if __name__ == "__main__":
    update_homebrew()

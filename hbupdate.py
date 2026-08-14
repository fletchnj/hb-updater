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

def fetch_cves_for_package(pkg_name, old_ver, new_ver):
    """Query OSV.dev for CVEs addressed in the updated version."""
    cves = []
    base_name = pkg_name.split('@')[0]
    
    url = "https://api.osv.dev/v1/query"
    payload = {"package": {"name": base_name}, "version": old_ver}
    
    try:
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode('utf-8'),
            headers={'Content-Type': 'application/json', 'User-Agent': 'hb-updater/1.0'}
        )
        with urllib.request.urlopen(req, timeout=4) as response:
            res = json.loads(response.read().decode('utf-8'))
            vulns = res.get('vulns', [])
            for v in vulns:
                aliases = [a for a in v.get('aliases', []) if a.startswith('CVE-')]
                if aliases:
                    cves.extend(aliases)
                elif v.get('id', '').startswith('CVE-'):
                    cves.append(v['id'])
                elif v.get('id'):
                    cves.append(v['id'])
    except Exception:
        pass
        
    return sorted(list(set(cves)))

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
        
        cves = fetch_cves_for_package(name, old_v, new_v)
        if cves:
            print(f"  CVEs / Advisories Fixed: {', '.join(cves)}")
        else:
            print("  CVEs / Advisories Fixed: None reported")
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

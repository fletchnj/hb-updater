#!/usr/bin/env python3

import subprocess

def run_command(cmd):
    """Run a shell command and stream its output."""
    process = subprocess.Popen(
        cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
    )
    for line in process.stdout:
        print(line, end="")
    process.wait()
    return process.returncode

def update_homebrew():
    print("Updating Homebrew...")
    if run_command("brew update") != 0:
        print("Failed to update Homebrew.")
        return

    print("\nUpgrading installed packages...")
    if run_command("brew upgrade") != 0:
        print("Failed to upgrade packages.")
        return

    print("\nCleaning up old Homebrew files...")
    run_command("brew cleanup")

    print("\nHomebrew update complete!")

if __name__ == "__main__":
    update_homebrew()


# Title: Time Machine Backup Disabled Via Tmutil - MacOS
# ID: 2c95fa8a-8b8d-4787-afce-7117ceb8e3da
# Status: test
# Level: medium
# Author: Pratinav Chandra
# Date: 2024-05-29
# Tags: attack.impact, attack.t1490
# Description: Detects disabling of Time Machine (Apple's automated backup utility software) via the native macOS backup utility "tmutil".
# An attacker can use this to prevent backups from occurring.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Time Machine Backup Disabled Via Tmutil - MacOS
def rule(event):
    # Detection Logic:
    # ((CommandLine="*disable*") AND ((Image="*/tmutil") OR (CommandLine="*tmutil*")))
    return True

def title(event):
    return "Time Machine Backup Disabled Via Tmutil - MacOS"


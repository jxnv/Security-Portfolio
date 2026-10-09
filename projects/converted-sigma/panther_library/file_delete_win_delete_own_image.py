# Title: Process Deletion of Its Own Executable
# ID: f01d1f70-cd41-42ec-9c0b-26dd9c22bf29
# Status: test
# Level: medium
# Author: Max Altgelt (Nextron Systems)
# Date: 2024-09-03
# Tags: attack.stealth
# Description: Detects the deletion of a process's executable by itself. This is usually not possible without workarounds and may be used by malware to hide its traces.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Process Deletion of Its Own Executable
def rule(event):
    # Detection Logic:
    # (TargetFilename=Image)
    return True

def title(event):
    return "Process Deletion of Its Own Executable"


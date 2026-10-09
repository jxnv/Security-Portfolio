# Title: Suspicious Process Execution From Fake Recycle.Bin Folder
# ID: 5ce0f04e-3efc-42af-839d-5b3a543b76c0
# Status: test
# Level: high
# Author: X__Junior (Nextron Systems)
# Date: 2023-07-12
# Tags: attack.persistence, attack.stealth
# Description: Detects process execution from a fake recycle bin folder, often used to avoid security solution.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Suspicious Process Execution From Fake Recycle.Bin Folder
def rule(event):
    # Detection Logic:
    # ((Image="*RECYCLERS.BIN\\*" OR Image="*RECYCLER.BIN\\*"))
    return True

def title(event):
    return "Suspicious Process Execution From Fake Recycle.Bin Folder"


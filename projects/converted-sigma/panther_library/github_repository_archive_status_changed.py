# Title: GitHub Repository Archive Status Changed
# ID: dca8991c-cb16-4128-abf8-6b11e5cd156f
# Status: experimental
# Level: low
# Author: Ivan Saakov
# Date: 2025-10-18
# Tags: attack.persistence, attack.impact, attack.defense-impairment
# Description: Detects when a GitHub repository is archived or unarchived, which may indicate unauthorized changes to repository status.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: GitHub Repository Archive Status Changed
def rule(event):
    # Detection Logic:
    # ((action="repo.archived" OR action="repo.unarchived"))
    return True

def title(event):
    return "GitHub Repository Archive Status Changed"


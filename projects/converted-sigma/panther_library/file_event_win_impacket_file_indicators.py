# Title: HackTool - Impacket File Indicators
# ID: 03f4ca17-de95-428d-a75a-4ee78b047256
# Status: experimental
# Level: high
# Author: The DFIR Report, IrishDeath
# Date: 2025-05-19
# Tags: attack.credential-access, attack.t1003.001
# Description: Detects file creation events with filename patterns used by Impacket.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: HackTool - Impacket File Indicators
def rule(event):
    # Detection Logic:
    # (TargetFilename=regex("\\\\sessionresume_[a-zA-Z]{8}$"))
    return True

def title(event):
    return "HackTool - Impacket File Indicators"


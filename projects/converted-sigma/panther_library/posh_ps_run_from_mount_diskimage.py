# Title: Suspicious Invoke-Item From Mount-DiskImage
# ID: 902cedee-0398-4e3a-8183-6f3a89773a96
# Status: test
# Level: medium
# Author: frack113
# Date: 2022-02-01
# Tags: attack.defense-impairment, attack.t1553.005
# Description: Adversaries may abuse container files such as disk image (.iso, .vhd) file formats to deliver malicious payloads that may not be tagged with MOTW.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Suspicious Invoke-Item From Mount-DiskImage
def rule(event):
    # Detection Logic:
    # ((ScriptBlockText="*Mount-DiskImage *" AND ScriptBlockText="*-ImagePath *" AND ScriptBlockText="*Get-Volume*" AND ScriptBlockText="*.DriveLetter*" AND ScriptBlockText="*invoke-item *" AND ScriptBlockText="*):\\*"))
    return True

def title(event):
    return "Suspicious Invoke-Item From Mount-DiskImage"


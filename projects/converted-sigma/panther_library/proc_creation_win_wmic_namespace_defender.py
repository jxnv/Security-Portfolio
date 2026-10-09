# Title: Potential Windows Defender Tampering Via Wmic.EXE
# ID: 51cbac1e-eee3-4a90-b1b7-358efb81fa0a
# Status: test
# Level: high
# Author: frack113
# Date: 2022-12-11
# Tags: attack.execution, attack.defense-impairment, attack.t1047, attack.t1685
# Description: Detects potential tampering with Windows Defender settings such as adding exclusion using wmic
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Potential Windows Defender Tampering Via Wmic.EXE
def rule(event):
    # Detection Logic:
    # ((CommandLine="*/Namespace:\\\\\\\\root\\\\Microsoft\\\\Windows\\\\Defender*") AND ((OriginalFileName="wmic.exe") OR (Image="*\\WMIC.exe")))
    return True

def title(event):
    return "Potential Windows Defender Tampering Via Wmic.EXE"


# Title: PUA - DefenderCheck Execution
# ID: f0ca6c24-3225-47d5-b1f5-352bf07ecfa7
# Status: test
# Level: high
# Author: Florian Roth (Nextron Systems)
# Date: 2022-08-30
# Tags: attack.stealth, attack.t1027.005
# Description: Detects the use of DefenderCheck, a tool to evaluate the signatures used in Microsoft Defender. It can be used to figure out the strings / byte chains used in Microsoft Defender to detect a tool and thus used for AV evasion.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: PUA - DefenderCheck Execution
def rule(event):
    # Detection Logic:
    # ((Image="*\\DefenderCheck.exe") OR (Description="DefenderCheck"))
    return True

def title(event):
    return "PUA - DefenderCheck Execution"


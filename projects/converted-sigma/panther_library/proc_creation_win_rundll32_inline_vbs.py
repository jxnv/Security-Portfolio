# Title: Suspicious Rundll32 Invoking Inline VBScript
# ID: 1cc50f3f-1fc8-4acf-b2e9-6f172e1fdebd
# Status: test
# Level: high
# Author: Florian Roth (Nextron Systems)
# Date: 2021-03-05
# Tags: attack.privilege-escalation, attack.stealth, attack.t1055
# Description: Detects suspicious process related to rundll32 based on command line that invokes inline VBScript as seen being used by UNC2452
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Suspicious Rundll32 Invoking Inline VBScript
def rule(event):
    # Detection Logic:
    # ((CommandLine="*rundll32.exe*" AND CommandLine="*Execute*" AND CommandLine="*RegRead*" AND CommandLine="*window.close*"))
    return True

def title(event):
    return "Suspicious Rundll32 Invoking Inline VBScript"


# Title: SafeBoot Registry Key Deleted Via Reg.EXE
# ID: fc0e89b5-adb0-43c1-b749-c12a10ec37de
# Status: test
# Level: high
# Author: Nasreddine Bencherchali (Nextron Systems), Tim Shelton
# Date: 2022-08-08
# Tags: attack.defense-impairment, attack.t1685
# Description: Detects execution of "reg.exe" commands with the "delete" flag on safe boot registry keys. Often used by attacker to prevent safeboot execution of security products
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: SafeBoot Registry Key Deleted Via Reg.EXE
def rule(event):
    # Detection Logic:
    # (((CommandLine="* delete *" AND CommandLine="*\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot*")) AND ((Image="*reg.exe") OR (OriginalFileName="reg.exe")))
    return True

def title(event):
    return "SafeBoot Registry Key Deleted Via Reg.EXE"


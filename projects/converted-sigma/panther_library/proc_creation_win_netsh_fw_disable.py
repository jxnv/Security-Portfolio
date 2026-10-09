# Title: Firewall Disabled via Netsh.EXE
# ID: 57c4bf16-227f-4394-8ec7-1b745ee061c3
# Status: test
# Level: medium
# Author: Fatih Sirin
# Date: 2019-11-01
# Tags: attack.defense-impairment, attack.t1686.003, attack.s0108
# Description: Detects netsh commands that turns off the Windows firewall
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Firewall Disabled via Netsh.EXE
def rule(event):
    # Detection Logic:
    # (((Image="*\\netsh.exe") OR (OriginalFileName="netsh.exe")) AND (((CommandLine="*firewall*" AND CommandLine="*set*" AND CommandLine="*opmode*" AND CommandLine="*disable*")) OR ((CommandLine="*advfirewall*" AND CommandLine="*set*" AND CommandLine="*state*" AND CommandLine="*off*"))))
    return True

def title(event):
    return "Firewall Disabled via Netsh.EXE"


# Title: DLL Execution via Rasautou.exe
# ID: cd3d1298-eb3b-476c-ac67-12847de55813
# Status: test
# Level: medium
# Author: Julia Fomina, oscd.community
# Date: 2020-10-09
# Tags: attack.stealth, attack.t1218
# Description: Detects using Rasautou.exe for loading arbitrary .DLL specified in -d option and executes the export specified in -p.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: DLL Execution via Rasautou.exe
def rule(event):
    # Detection Logic:
    # (((CommandLine="* -d *" AND CommandLine="* -p *")) AND ((Image="*\\rasautou.exe") OR (OriginalFileName="rasdlui.exe")))
    return True

def title(event):
    return "DLL Execution via Rasautou.exe"


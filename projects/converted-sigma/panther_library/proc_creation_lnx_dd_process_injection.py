# Title: Potential Linux Process Code Injection Via DD Utility
# ID: 4cad6c64-d6df-42d6-8dae-eb78defdc415
# Status: test
# Level: medium
# Author: Joseph Kamau
# Date: 2023-12-01
# Tags: attack.privilege-escalation, attack.stealth, attack.t1055.009
# Description: Detects the injection of code by overwriting the memory map of a Linux process using the "dd" Linux command.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Potential Linux Process Code Injection Via DD Utility
def rule(event):
    # Detection Logic:
    # (Image="*/dd" AND (CommandLine="*of=*" AND CommandLine="*/proc/*" AND CommandLine="*/mem*"))
    return True

def title(event):
    return "Potential Linux Process Code Injection Via DD Utility"


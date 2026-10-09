# Title: System Language Discovery via Reg.Exe
# ID: c43a5405-e8e1-4221-9ac9-dbe3fa14e886
# Status: experimental
# Level: medium
# Author: Marco Pedrinazzi (@pedrinazziM) (InTheCyber)
# Date: 2026-01-09
# Tags: attack.discovery, attack.t1614.001
# Description: Detects the usage of Reg.Exe to query system language settings.
# Attackers may discover the system language to determine the geographic location of victims, customize payloads for specific regions,
# or avoid targeting certain locales to evade detection.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: System Language Discovery via Reg.Exe
def rule(event):
    # Detection Logic:
    # (((CommandLine="*query*" AND CommandLine="*Control\\Nls\\Language*")) AND ((Image="*\\reg.exe") OR (OriginalFileName="reg.exe")))
    return True

def title(event):
    return "System Language Discovery via Reg.Exe"


# Title: Suspicious Driver/DLL Installation Via Odbcconf.EXE
# ID: cb0fe7c5-f3a3-484d-aa25-d350a7912729
# Status: test
# Level: high
# Author: Nasreddine Bencherchali (Nextron Systems)
# Date: 2023-05-23
# Tags: attack.stealth, attack.t1218.008
# Description: Detects execution of "odbcconf" with the "INSTALLDRIVER" action where the driver doesn't contain a ".dll" extension. This is often used as a defense evasion method.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Suspicious Driver/DLL Installation Via Odbcconf.EXE
def rule(event):
    # Detection Logic:
    # (((CommandLine="*INSTALLDRIVER *") AND ((Image="*\\odbcconf.exe") OR (OriginalFileName="odbcconf.exe"))) AND NOT ((CommandLine="*.dll*")))
    return True

def title(event):
    return "Suspicious Driver/DLL Installation Via Odbcconf.EXE"


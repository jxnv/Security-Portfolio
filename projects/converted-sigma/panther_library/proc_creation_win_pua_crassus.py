# Title: PUA - Crassus Execution
# ID: 2c32b543-1058-4808-91c6-5b31b8bed6c5
# Status: test
# Level: high
# Author: pH-T (Nextron Systems)
# Date: 2023-04-17
# Tags: attack.discovery, attack.reconnaissance, attack.t1590.001
# Description: Detects Crassus, a Windows privilege escalation discovery tool, based on PE metadata characteristics.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: PUA - Crassus Execution
def rule(event):
    # Detection Logic:
    # ((Image="*\\Crassus.exe") OR (OriginalFileName="Crassus.exe") OR (Description="*Crassus*"))
    return True

def title(event):
    return "PUA - Crassus Execution"


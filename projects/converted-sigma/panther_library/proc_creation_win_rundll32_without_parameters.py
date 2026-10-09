# Title: Rundll32 Execution Without Parameters
# ID: 5bb68627-3198-40ca-b458-49f973db8752
# Status: test
# Level: high
# Author: Bartlomiej Czyz, Relativity
# Date: 2021-01-31
# Tags: attack.lateral-movement, attack.t1021.002, attack.t1570, attack.execution, attack.t1569.002
# Description: Detects rundll32 execution without parameters as observed when running Metasploit windows/smb/psexec exploit module
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Rundll32 Execution Without Parameters
def rule(event):
    # Detection Logic:
    # ((CommandLine="rundll32.exe" OR CommandLine="rundll32"))
    return True

def title(event):
    return "Rundll32 Execution Without Parameters"


# Title: Potentially Suspicious DMP/HDMP File Creation
# ID: aba15bdd-657f-422a-bab3-ac2d2a0d6f1c
# Status: test
# Level: medium
# Author: Nasreddine Bencherchali (Nextron Systems)
# Date: 2023-09-07
# Tags: attack.stealth
# Description: Detects the creation of a file with the ".dmp"/".hdmp" extension by a shell or scripting application such as "cmd", "powershell", etc. Often created by software during a crash. Memory dumps can sometimes contain sensitive information such as credentials. It's best to determine the source of the crash.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Potentially Suspicious DMP/HDMP File Creation
def rule(event):
    # Detection Logic:
    # ((Image="*\\cmd.exe" OR Image="*\\cscript.exe" OR Image="*\\mshta.exe" OR Image="*\\powershell.exe" OR Image="*\\pwsh.exe" OR Image="*\\wscript.exe") AND (TargetFilename="*.dmp" OR TargetFilename="*.dump" OR TargetFilename="*.hdmp"))
    return True

def title(event):
    return "Potentially Suspicious DMP/HDMP File Creation"


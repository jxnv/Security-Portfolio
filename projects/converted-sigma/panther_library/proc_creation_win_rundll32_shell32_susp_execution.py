# Title: Shell32 DLL Execution in Suspicious Directory
# ID: 32b96012-7892-429e-b26c-ac2bf46066ff
# Status: test
# Level: high
# Author: Christian Burkard (Nextron Systems)
# Date: 2021-11-24
# Tags: attack.execution, attack.stealth, attack.t1218.011
# Description: Detects shell32.dll executing a DLL in a suspicious directory
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Shell32 DLL Execution in Suspicious Directory
def rule(event):
    # Detection Logic:
    # (((CommandLine="*shell32.dll*" AND CommandLine="*Control_RunDLL*") AND (CommandLine="*%AppData%*" OR CommandLine="*%LocalAppData%*" OR CommandLine="*%Temp%*" OR CommandLine="*%tmp%*" OR CommandLine="*\\AppData\\*" OR CommandLine="*\\Temp\\*" OR CommandLine="*\\Users\\Public\\*")) AND ((Image="*\\rundll32.exe") OR (OriginalFileName="RUNDLL32.EXE")))
    return True

def title(event):
    return "Shell32 DLL Execution in Suspicious Directory"


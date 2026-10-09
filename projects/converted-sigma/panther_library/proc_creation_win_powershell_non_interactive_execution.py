# Title: Non Interactive PowerShell Process Spawned
# ID: f4bbd493-b796-416e-bbf2-121235348529
# Status: test
# Level: low
# Author: Roberto Rodriguez @Cyb3rWard0g (rule), oscd.community (improvements)
# Date: 2019-09-12
# Tags: attack.execution, attack.t1059.001
# Description: Detects non-interactive PowerShell activity by looking at the "powershell" process with a non-user GUI process such as "explorer.exe" as a parent.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Non Interactive PowerShell Process Spawned
def rule(event):
    # Detection Logic:
    # ((((Image="*\\powershell.exe" OR Image="*\\pwsh.exe")) OR ((OriginalFileName="PowerShell.EXE" OR OriginalFileName="pwsh.dll"))) AND NOT ((((ParentImage="*:\\Windows\\explorer.exe" OR ParentImage="*:\\Windows\\System32\\CompatTelRunner.exe" OR ParentImage="*:\\Windows\\SysWOW64\\explorer.exe")) OR (ParentImage=":\\$WINDOWS.~BT\\Sources\\SetupHost.exe"))) AND NOT (((ParentImage="*:\\Program Files\\Windows Defender Advanced Threat Protection\\SenseIR.exe") OR (ParentImage="*:\\Program Files\\WindowsApps\\Microsoft.WindowsTerminal_*" AND ParentImage="*\\WindowsTerminal.exe") OR (ParentImage="*\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe" AND ParentCommandLine="* --ms-enable-electron-run-as-node *"))))
    return True

def title(event):
    return "Non Interactive PowerShell Process Spawned"


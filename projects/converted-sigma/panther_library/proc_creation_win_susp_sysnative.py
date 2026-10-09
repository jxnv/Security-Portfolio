# Title: Process Creation Using Sysnative Folder
# ID: 3c1b5fb0-c72f-45ba-abd1-4d4c353144ab
# Status: test
# Level: medium
# Author: Max Altgelt (Nextron Systems)
# Date: 2022-08-23
# Tags: attack.privilege-escalation, attack.stealth, attack.t1055
# Description: Detects process creation events that use the Sysnative folder (common for CobaltStrike spawns)
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Process Creation Using Sysnative Folder
def rule(event):
    # Detection Logic:
    # (((CommandLine="*:\\Windows\\Sysnative\\*") OR (Image="*:\\Windows\\Sysnative\\*")) AND NOT (((Image="*C:\\Windows\\Microsoft.NET\\Framework64\\v*" OR Image="*C:\\Windows\\Microsoft.NET\\Framework\\v*" OR Image="*C:\\Windows\\Microsoft.NET\\FrameworkArm\\v*" OR Image="*C:\\Windows\\Microsoft.NET\\FrameworkArm64\\v*") AND Image="*\\ngen.exe" AND CommandLine="*install*")) AND NOT (((CommandLine="*\"C:\\Windows\\sysnative\\cmd.exe\"*" AND CommandLine="*\\xampp\\*" AND CommandLine="*\\catalina_start.bat*"))))
    return True

def title(event):
    return "Process Creation Using Sysnative Folder"


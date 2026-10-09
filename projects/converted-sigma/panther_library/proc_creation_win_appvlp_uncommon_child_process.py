# Title: Uncommon Child Process Of Appvlp.EXE
# ID: 9c7e131a-0f2c-4ae0-9d43-b04f4e266d43
# Status: test
# Level: medium
# Author: Sreeman
# Date: 2020-03-13
# Tags: attack.stealth, attack.t1218, attack.execution
# Description: Detects uncommon child processes of Appvlp.EXE
# Appvlp or the Application Virtualization Utility is included with Microsoft Office. Attackers are able to abuse "AppVLP" to execute shell commands.
# Normally, this binary is used for Application Virtualization, but it can also be abused to circumvent the ASR file path rule folder
# or to mark a file as a system file.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Uncommon Child Process Of Appvlp.EXE
def rule(event):
    # Detection Logic:
    # ((ParentImage="*\\appvlp.exe") AND NOT (((Image="*:\\Windows\\SysWOW64\\rundll32.exe" OR Image="*:\\Windows\\System32\\rundll32.exe"))) AND NOT (((Image="*:\\Program Files\\Microsoft Office*" AND Image="*\\msoasb.exe") OR (Image="*:\\Program Files\\Microsoft Office*" AND Image="*\\MSOUC.EXE") OR ((Image="*:\\Program Files\\Microsoft Office*" AND Image="*\\SkypeSrv\\*") AND Image="*\\SKYPESERVER.EXE"))))
    return True

def title(event):
    return "Uncommon Child Process Of Appvlp.EXE"


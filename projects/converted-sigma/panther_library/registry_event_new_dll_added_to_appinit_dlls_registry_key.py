# Title: New DLL Added to AppInit_DLLs Registry Key
# ID: 4f84b697-c9ed-4420-8ab5-e09af5b2345d
# Status: test
# Level: medium
# Author: Ilyas Ochkov, oscd.community, Tim Shelton
# Date: 2019-10-25
# Tags: attack.privilege-escalation, attack.persistence, attack.t1546.010
# Description: DLLs that are specified in the AppInit_DLLs value in the Registry key HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows are loaded by user32.dll into every process that loads user32.dll
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: New DLL Added to AppInit_DLLs Registry Key
def rule(event):
    # Detection Logic:
    # ((((TargetObject="*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_Dlls" OR TargetObject="*\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_Dlls")) OR ((NewName="*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_Dlls" OR NewName="*\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_Dlls"))) AND NOT ((Details="(Empty)")))
    return True

def title(event):
    return "New DLL Added to AppInit_DLLs Registry Key"


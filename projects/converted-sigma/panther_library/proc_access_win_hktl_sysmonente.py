# Title: HackTool - SysmonEnte Execution
# ID: d29ada0f-af45-4f27-8f32-f7b77c3dbc4e
# Status: test
# Level: high
# Author: Florian Roth (Nextron Systems)
# Date: 2022-09-07
# Tags: attack.defense-impairment, attack.t1685.001
# Description: Detects the use of SysmonEnte, a tool to attack the integrity of Sysmon
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: HackTool - SysmonEnte Execution
def rule(event):
    # Detection Logic:
    # ((((TargetImage="*:\\Windows\\Sysmon.exe*" OR TargetImage="*:\\Windows\\Sysmon64.exe*" OR TargetImage="*:\\Windows\\Sysmon64a.exe*") AND GrantedAccess="0x1400") AND NOT ((((SourceImage="*:\\Program Files (x86)\\*" OR SourceImage="*:\\Program Files\\*" OR SourceImage="*:\\Windows\\System32\\*" OR SourceImage="*:\\Windows\\SysWOW64\\*")) OR (SourceImage="*:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\*" AND SourceImage="*\\MsMpEng.exe")))) OR (CallTrace="Ente"))
    return True

def title(event):
    return "HackTool - SysmonEnte Execution"


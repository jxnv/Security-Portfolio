# Title: File Download Via Windows Defender MpCmpRun.EXE
# ID: 46123129-1024-423e-9fae-43af4a0fa9a5
# Status: test
# Level: high
# Author: Matthew Matchen
# Date: 2020-09-04
# Tags: attack.stealth, attack.t1218, attack.command-and-control, attack.t1105
# Description: Detects the use of Windows Defender MpCmdRun.EXE to download files
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: File Download Via Windows Defender MpCmpRun.EXE
def rule(event):
    # Detection Logic:
    # (((CommandLine="*DownloadFile*" AND CommandLine="*url*")) AND ((OriginalFileName="MpCmdRun.exe") OR (Image="*\\MpCmdRun.exe") OR (CommandLine="*MpCmdRun.exe*") OR (Description="Microsoft Malware Protection Command Line Utility")))
    return True

def title(event):
    return "File Download Via Windows Defender MpCmpRun.EXE"


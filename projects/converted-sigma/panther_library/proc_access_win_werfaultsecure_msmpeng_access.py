# Title: Suspicious Process Access of MsMpEng by WerFaultSecure - EDR-Freeze
# ID: 387df17d-3b04-448f-8669-9e7fd5e5fd8c
# Status: experimental
# Level: high
# Author: Swachchhanda Shrawan Poudel (Nextron Systems)
# Date: 2025-11-27
# Tags: attack.defense-impairment, attack.t1685
# Description: Detects process access events where WerFaultSecure accesses MsMpEng.exe with dbgcore.dll or dbghelp.dll in the call trace, indicating potential EDR freeze techniques.
# This technique leverages WerFaultSecure.exe running as a Protected Process Light (PPL) with WinTCB protection level to call MiniDumpWriteDump and suspend EDR/AV processes, allowing malicious activity to execute undetected during the suspension period.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Suspicious Process Access of MsMpEng by WerFaultSecure - EDR-Freeze
def rule(event):
    # Detection Logic:
    # (SourceImage="*\\WerFaultSecure.exe" AND TargetImage="*\\MsMpEng.exe" AND (CallTrace="*\\dbgcore.dll*" OR CallTrace="*\\dbghelp.dll*"))
    return True

def title(event):
    return "Suspicious Process Access of MsMpEng by WerFaultSecure - EDR-Freeze"


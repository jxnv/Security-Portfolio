# Title: Credential Dumping Activity By Python Based Tool
# ID: f8be3e82-46a3-4e4e-ada5-8e538ae8b9c9
# Status: stable
# Level: high
# Author: Bhabesh Raj, Jonhnathan Ribeiro
# Date: 2023-11-27
# Tags: attack.credential-access, attack.t1003.001, attack.s0349
# Description: Detects LSASS process access for potential credential dumping by a Python-like tool such as LaZagne or Pypykatz.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Credential Dumping Activity By Python Based Tool
def rule(event):
    # Detection Logic:
    # (TargetImage="*\\lsass.exe" AND (CallTrace="*_ctypes.pyd+*" AND CallTrace="*:\\Windows\\System32\\KERNELBASE.dll+*" AND CallTrace="*:\\Windows\\SYSTEM32\\ntdll.dll+*") AND (CallTrace="*python27.dll+*" OR CallTrace="*python3*.dll+*") AND GrantedAccess="0x1FFFFF")
    return True

def title(event):
    return "Credential Dumping Activity By Python Based Tool"


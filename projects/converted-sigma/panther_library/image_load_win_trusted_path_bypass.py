# Title: Trusted Path Bypass via Windows Directory Spoofing
# ID: 0cbe38c0-270c-41d9-ab79-6e5a9a669290
# Status: experimental
# Level: high
# Author: Swachchhanda Shrawan Poudel (Nextron Systems)
# Date: 2025-06-17
# Tags: attack.persistence, attack.privilege-escalation, attack.execution, attack.stealth, attack.t1574.007, attack.t1548.002
# Description: Detects DLLs loading from a spoofed Windows directory path with an extra space (e.g "C:\Windows \System32") which can bypass Windows trusted path verification.
# This technique tricks Windows into treating the path as trusted, allowing malicious DLLs to load with high integrity privileges bypassing UAC.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Trusted Path Bypass via Windows Directory Spoofing
def rule(event):
    # Detection Logic:
    # ((ImageLoaded="*:\\Windows \\System32\\*" OR ImageLoaded="*:\\Windows \\SysWOW64\\*"))
    return True

def title(event):
    return "Trusted Path Bypass via Windows Directory Spoofing"


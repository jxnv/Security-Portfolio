# Title: Potential Ransomware or Unauthorized MBR Tampering Via Bcdedit.EXE
# ID: c9fbe8e9-119d-40a6-9b59-dd58a5d84429
# Status: test
# Level: medium
# Author: @neu5ron
# Date: 2019-02-07
# Tags: attack.stealth, attack.t1070, attack.persistence, attack.t1542.003
# Description: Detects potential malicious and unauthorized usage of bcdedit.exe
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Potential Ransomware or Unauthorized MBR Tampering Via Bcdedit.EXE
def rule(event):
    # Detection Logic:
    # (((CommandLine="*delete*" OR CommandLine="*deletevalue*" OR CommandLine="*import*" OR CommandLine="*safeboot*" OR CommandLine="*network*")) AND ((Image="*\\bcdedit.exe") OR (OriginalFileName="bcdedit.exe")))
    return True

def title(event):
    return "Potential Ransomware or Unauthorized MBR Tampering Via Bcdedit.EXE"


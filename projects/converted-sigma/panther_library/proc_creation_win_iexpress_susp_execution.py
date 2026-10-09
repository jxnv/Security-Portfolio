# Title: Self Extracting Package Creation Via Iexpress.EXE From Potentially Suspicious Location
# ID: b2b048b0-7857-4380-b0fb-d3f0ab820b71
# Status: test
# Level: high
# Author: Joseliyo Sanchez, @Joseliyo_Jstnk, Nasreddine Bencherchali (Nextron Systems)
# Date: 2024-02-05
# Tags: attack.stealth, attack.t1218
# Description: Detects the use of iexpress.exe to create binaries via Self Extraction Directive (SED) files located in potentially suspicious locations.
# This behavior has been observed in-the-wild by different threat actors.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Self Extracting Package Creation Via Iexpress.EXE From Potentially Suspicious Location
def rule(event):
    # Detection Logic:
    # ((CommandLine="* /n *") AND ((Image="*\\iexpress.exe") OR (OriginalFileName="IEXPRESS.exe")) AND ((CommandLine="*:\\ProgramData\\*" OR CommandLine="*:\\Temp\\*" OR CommandLine="*:\\Windows\\System32\\Tasks\\*" OR CommandLine="*:\\Windows\\Tasks\\*" OR CommandLine="*:\\Windows\\Temp\\*" OR CommandLine="*\\AppData\\Local\\Temp\\*")))
    return True

def title(event):
    return "Self Extracting Package Creation Via Iexpress.EXE From Potentially Suspicious Location"


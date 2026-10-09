# Title: Process Memory Dump via RdrLeakDiag.EXE
# ID: edadb1e5-5919-4e4c-8462-a9e643b02c4b
# Status: test
# Level: high
# Author: Cedric MAURUGEON, Florian Roth (Nextron Systems), Swachchhanda Shrawan Poudel, Nasreddine Bencherchali (Nextron Systems)
# Date: 2021-09-24
# Tags: attack.credential-access, attack.t1003.001
# Description: Detects the use of the Microsoft Windows Resource Leak Diagnostic tool "rdrleakdiag.exe" to dump process memory
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Process Memory Dump via RdrLeakDiag.EXE
def rule(event):
    # Detection Logic:
    # (((CommandLine="*/memdmp*" OR CommandLine="*-memdmp*" OR CommandLine="*fullmemdmp*")) AND ((CommandLine="* /o *" OR CommandLine="* /p *")) AND ((Image="*\\rdrleakdiag.exe") OR (OriginalFileName="RdrLeakDiag.exe")))
    return True

def title(event):
    return "Process Memory Dump via RdrLeakDiag.EXE"


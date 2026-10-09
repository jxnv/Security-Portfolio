# Title: Suspicious Windows Trace ETW Session Tamper Via Logman.EXE
# ID: cd1f961e-0b96-436b-b7c6-38da4583ec00
# Status: test
# Level: high
# Author: Florian Roth (Nextron Systems)
# Date: 2021-02-11
# Tags: attack.defense-impairment, attack.t1685, attack.t1685.005
# Description: Detects the execution of "logman" utility in order to disable or delete Windows trace sessions
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Suspicious Windows Trace ETW Session Tamper Via Logman.EXE
def rule(event):
    # Detection Logic:
    # (((CommandLine="*stop *" OR CommandLine="*delete *")) AND ((Image="*\\logman.exe") OR (OriginalFileName="Logman.exe")) AND ((CommandLine="*Circular Kernel Context Logger*" OR CommandLine="*EventLog-*" OR CommandLine="*SYSMON TRACE*" OR CommandLine="*SysmonDnsEtwSession*")))
    return True

def title(event):
    return "Suspicious Windows Trace ETW Session Tamper Via Logman.EXE"


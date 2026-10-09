# Title: Service Started/Stopped Via Wmic.EXE
# ID: 0b7163dc-7eee-4960-af17-c0cd517f92da
# Status: test
# Level: medium
# Author: Nasreddine Bencherchali (Nextron Systems)
# Date: 2022-06-20
# Tags: attack.execution, attack.t1047
# Description: Detects usage of wmic to start or stop a service
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Service Started/Stopped Via Wmic.EXE
def rule(event):
    # Detection Logic:
    # (((CommandLine="* service *" AND CommandLine="* call *") AND (CommandLine="*stopservice*" OR CommandLine="*startservice*")) AND ((OriginalFileName="wmic.exe") OR (Image="*\\WMIC.exe")))
    return True

def title(event):
    return "Service Started/Stopped Via Wmic.EXE"


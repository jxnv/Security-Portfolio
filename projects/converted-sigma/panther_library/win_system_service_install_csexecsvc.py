# Title: CSExec Service Installation
# ID: a27e5fa9-c35e-4e3d-b7e0-1ce2af66ad12
# Status: test
# Level: medium
# Author: Nasreddine Bencherchali (Nextron Systems)
# Date: 2023-08-07
# Tags: attack.execution, attack.t1569.002
# Description: Detects CSExec service installation and execution events
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: CSExec Service Installation
def rule(event):
    # Detection Logic:
    # ((Provider_Name="Service Control Manager" AND EventID="7045") AND ((ServiceName="csexecsvc") OR (ImagePath="*\\csexecsvc.exe")))
    return True

def title(event):
    return "CSExec Service Installation"


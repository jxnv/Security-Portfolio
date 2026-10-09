# Title: PsExec Service File Creation
# ID: 259e5a6a-b8d2-4c38-86e2-26c5e651361d
# Status: test
# Level: low
# Author: Thomas Patzke
# Date: 2017-06-12
# Tags: attack.execution, attack.t1569.002, attack.s0029
# Description: Detects default PsExec service filename which indicates PsExec service installation and execution
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: PsExec Service File Creation
def rule(event):
    # Detection Logic:
    # (TargetFilename="*\\PSEXESVC.exe")
    return True

def title(event):
    return "PsExec Service File Creation"


# Title: Suspicious Diantz Download and Compress Into a CAB File
# ID: 185d7418-f250-42d0-b72e-0c8b70661e93
# Status: test
# Level: medium
# Author: frack113
# Date: 2021-11-26
# Tags: attack.command-and-control, attack.t1105
# Description: Download and compress a remote file and store it in a cab file on local machine.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Suspicious Diantz Download and Compress Into a CAB File
def rule(event):
    # Detection Logic:
    # ((CommandLine="*diantz.exe*" AND CommandLine="* \\\\\\\\*" AND CommandLine="*.cab*"))
    return True

def title(event):
    return "Suspicious Diantz Download and Compress Into a CAB File"


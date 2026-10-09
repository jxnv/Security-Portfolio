# Title: Potential File Overwrite Via Sysinternals SDelete
# ID: a4824fca-976f-4964-b334-0621379e84c4
# Status: test
# Level: high
# Author: frack113
# Date: 2021-06-03
# Tags: attack.impact, attack.t1485
# Description: Detects the use of SDelete to erase a file not the free space
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Potential File Overwrite Via Sysinternals SDelete
def rule(event):
    # Detection Logic:
    # ((OriginalFileName="sdelete.exe") AND NOT (((CommandLine="* -h*" OR CommandLine="* -c*" OR CommandLine="* -z*" OR CommandLine="* /\\?*"))))
    return True

def title(event):
    return "Potential File Overwrite Via Sysinternals SDelete"


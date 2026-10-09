# Title: Replace.exe Usage
# ID: 9292293b-8496-4715-9db6-37028dcda4b3
# Status: test
# Level: medium
# Author: frack113
# Date: 2022-03-06
# Tags: attack.command-and-control, attack.t1105
# Description: Detects the use of Replace.exe which can be used to replace file with another file
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Replace.exe Usage
def rule(event):
    # Detection Logic:
    # ((Image="*\\replace.exe") AND ((CommandLine="*-a*" OR CommandLine="*/a*")))
    return True

def title(event):
    return "Replace.exe Usage"


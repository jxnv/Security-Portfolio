# Title: New Generic Credentials Added Via Cmdkey.EXE
# ID: b1ec66c6-f4d1-4b5c-96dd-af28ccae7727
# Status: test
# Level: medium
# Author: frack113, Nasreddine Bencherchali (Nextron Systems)
# Date: 2023-02-03
# Tags: attack.credential-access, attack.t1003.005
# Description: Detects usage of "cmdkey.exe" to add generic credentials.
# As an example, this can be used before connecting to an RDP session via command line interface.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: New Generic Credentials Added Via Cmdkey.EXE
def rule(event):
    # Detection Logic:
    # ((CommandLine="* -g*") AND (CommandLine="* -p*") AND (CommandLine="* -u*") AND ((Image="*\\cmdkey.exe") OR (OriginalFileName="cmdkey.exe")))
    return True

def title(event):
    return "New Generic Credentials Added Via Cmdkey.EXE"


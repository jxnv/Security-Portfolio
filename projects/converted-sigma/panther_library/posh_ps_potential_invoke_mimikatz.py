# Title: Potential Invoke-Mimikatz PowerShell Script
# ID: 189e3b02-82b2-4b90-9662-411eb64486d4
# Status: test
# Level: high
# Author: Tim Rauch, Elastic (idea)
# Date: 2022-09-28
# Tags: attack.credential-access, attack.t1003
# Description: Detects Invoke-Mimikatz PowerShell script and alike. Mimikatz is a credential dumper capable of obtaining plaintext Windows account logins and passwords.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Potential Invoke-Mimikatz PowerShell Script
def rule(event):
    # Detection Logic:
    # (((ScriptBlockText="*DumpCreds*" AND ScriptBlockText="*DumpCerts*")) OR (ScriptBlockText="*sekurlsa::logonpasswords*") OR ((ScriptBlockText="*crypto::certificates*" AND ScriptBlockText="*CERT_SYSTEM_STORE_LOCAL_MACHINE*")))
    return True

def title(event):
    return "Potential Invoke-Mimikatz PowerShell Script"


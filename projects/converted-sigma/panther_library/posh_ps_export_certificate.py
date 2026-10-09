# Title: Certificate Exported Via PowerShell - ScriptBlock
# ID: aa7a3fce-bef5-4311-9cc1-5f04bb8c308c
# Status: test
# Level: medium
# Author: Florian Roth (Nextron Systems)
# Date: 2021-04-23
# Tags: attack.credential-access, attack.t1552.004
# Description: Detects calls to cmdlets inside of PowerShell scripts that are used to export certificates from the local certificate store. Threat actors were seen abusing this to steal private keys from compromised machines.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Certificate Exported Via PowerShell - ScriptBlock
def rule(event):
    # Detection Logic:
    # (((ScriptBlockText="*Export-PfxCertificate*" OR ScriptBlockText="*Export-Certificate*")) AND NOT ((ScriptBlockText="*CmdletsToExport = @(*")))
    return True

def title(event):
    return "Certificate Exported Via PowerShell - ScriptBlock"


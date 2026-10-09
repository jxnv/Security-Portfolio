# Title: Disable-WindowsOptionalFeature Command PowerShell
# ID: 99c4658d-2c5e-4d87-828d-7c066ca537c3
# Status: test
# Level: high
# Author: frack113
# Date: 2022-09-10
# Tags: attack.defense-impairment, attack.t1685
# Description: Detect built in PowerShell cmdlet Disable-WindowsOptionalFeature, Deployment Image Servicing and Management tool.
# Similar to DISM.exe, this cmdlet is used to enumerate, install, uninstall, configure, and update features and packages in Windows images
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Disable-WindowsOptionalFeature Command PowerShell
def rule(event):
    # Detection Logic:
    # (((ScriptBlockText="*Disable-WindowsOptionalFeature*" AND ScriptBlockText="*-Online*" AND ScriptBlockText="*-FeatureName*")) AND ((ScriptBlockText="*Windows-Defender-Gui*" OR ScriptBlockText="*Windows-Defender-Features*" OR ScriptBlockText="*Windows-Defender*" OR ScriptBlockText="*Windows-Defender-ApplicationGuard*")))
    return True

def title(event):
    return "Disable-WindowsOptionalFeature Command PowerShell"


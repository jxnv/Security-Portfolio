# Title: DeviceCredentialDeployment Execution
# ID: b8b1b304-a60f-4999-9a6e-c547bde03ffd
# Status: test
# Level: medium
# Author: Nasreddine Bencherchali (Nextron Systems)
# Date: 2022-08-19
# Tags: attack.stealth, attack.t1218
# Description: Detects the execution of DeviceCredentialDeployment to hide a process from view.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: DeviceCredentialDeployment Execution
def rule(event):
    # Detection Logic:
    # (Image="*\\DeviceCredentialDeployment.exe")
    return True

def title(event):
    return "DeviceCredentialDeployment Execution"


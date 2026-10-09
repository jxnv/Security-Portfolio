# Title: RemoteFXvGPUDisablement Abuse Via AtomicTestHarnesses
# ID: a6fc3c46-23b8-4996-9ea2-573f4c4d88c5
# Status: test
# Level: high
# Author: frack113
# Date: 2021-07-13
# Tags: attack.stealth, attack.t1218
# Description: Detects calls to the AtomicTestHarnesses "Invoke-ATHRemoteFXvGPUDisablementCommand" which is designed to abuse the "RemoteFXvGPUDisablement.exe" binary to run custom PowerShell code via module load-order hijacking.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: RemoteFXvGPUDisablement Abuse Via AtomicTestHarnesses
def rule(event):
    # Detection Logic:
    # ((CommandLine="*Invoke-ATHRemoteFXvGPUDisablementCommand*" OR CommandLine="*Invoke-ATHRemoteFXvGPUDisableme*"))
    return True

def title(event):
    return "RemoteFXvGPUDisablement Abuse Via AtomicTestHarnesses"


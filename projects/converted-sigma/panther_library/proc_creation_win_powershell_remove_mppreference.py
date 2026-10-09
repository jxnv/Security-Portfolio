# Title: Tamper Windows Defender Remove-MpPreference
# ID: 07e3cb2c-0608-410d-be4b-1511cb1a0448
# Status: test
# Level: high
# Author: Nasreddine Bencherchali (Nextron Systems)
# Date: 2022-08-05
# Tags: attack.defense-impairment, attack.t1685
# Description: Detects attempts to remove Windows Defender configurations using the 'MpPreference' cmdlet
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Tamper Windows Defender Remove-MpPreference
def rule(event):
    # Detection Logic:
    # ((CommandLine="*Remove-MpPreference*") AND ((CommandLine="*-ControlledFolderAccessProtectedFolders *" OR CommandLine="*-AttackSurfaceReductionRules_Ids *" OR CommandLine="*-AttackSurfaceReductionRules_Actions *" OR CommandLine="*-CheckForSignaturesBeforeRunningScan *")))
    return True

def title(event):
    return "Tamper Windows Defender Remove-MpPreference"


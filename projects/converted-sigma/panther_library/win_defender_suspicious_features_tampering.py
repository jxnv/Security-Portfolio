# Title: Windows Defender Configuration Changes
# ID: 801bd44f-ceed-4eb6-887c-11544633c0aa
# Status: stable
# Level: high
# Author: Nasreddine Bencherchali (Nextron Systems)
# Date: 2022-12-06
# Tags: attack.defense-impairment, attack.t1685
# Description: Detects suspicious changes to the Windows Defender configuration
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Windows Defender Configuration Changes
def rule(event):
    # Detection Logic:
    # (EventID="5007" AND (NewValue="*\\Windows Defender\\DisableAntiSpyware *" OR NewValue="*\\Windows Defender\\Scan\\DisableRemovableDriveScanning *" OR NewValue="*\\Windows Defender\\Scan\\DisableScanningMappedNetworkDrivesForFullScan *" OR NewValue="*\\Windows Defender\\SpyNet\\DisableBlockAtFirstSeen *" OR NewValue="*\\Real-Time Protection\\SpyNetReporting *"))
    return True

def title(event):
    return "Windows Defender Configuration Changes"


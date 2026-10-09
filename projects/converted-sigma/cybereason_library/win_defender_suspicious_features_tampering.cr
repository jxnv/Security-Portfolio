// Title: Windows Defender Configuration Changes
// ID: 801bd44f-ceed-4eb6-887c-11544633c0aa
// Status: stable
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-12-06
// Tags: attack.defense-impairment, attack.t1685
// Description: Detects suspicious changes to the Windows Defender configuration
// Converted by: Sigma Universal SIEM/EDR CLI

(EventID == "5007" AND (NewValue contains "\\Windows Defender\\DisableAntiSpyware " OR NewValue contains "\\Windows Defender\\Scan\\DisableRemovableDriveScanning " OR NewValue contains "\\Windows Defender\\Scan\\DisableScanningMappedNetworkDrivesForFullScan " OR NewValue contains "\\Windows Defender\\SpyNet\\DisableBlockAtFirstSeen " OR NewValue contains "\\Real-Time Protection\\SpyNetReporting "))

// Title: HybridConnectionManager Service Installation - Registry
// ID: ac8866c7-ce44-46fd-8c17-b24acff96ca8
// Status: test
// Level: high
// Author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
// Date: 2021-04-12
// Tags: attack.resource-development, attack.t1608
// Description: Detects the installation of the Azure Hybrid Connection Manager service to allow remote code execution from Azure function.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((TargetObject contains "\\Services\\HybridConnectionManager") or (EventType = "SetValue" and Details contains "Microsoft.HybridConnectionManager.Listener.exe"))

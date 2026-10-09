// Title: Azure AD Health Monitoring Agent Registry Keys Access
// ID: ff151c33-45fa-475d-af4f-c2f93571f4fe
// Status: test
// Level: medium
// Author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research), MSTIC
// Date: 2021-08-26
// Tags: attack.discovery, attack.t1012
// Description: This detection uses Windows security events to detect suspicious access attempts to the registry key of Azure AD Health monitoring agent.
// This detection requires an access control entry (ACE) on the system access control list (SACL) of the following securable object HKLM\SOFTWARE\Microsoft\Microsoft Online\Reporting\MonitoringAgent.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((EventID = 4656 or EventID = 4663) and ObjectType = "Key" and ObjectName = "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Microsoft Online\\Reporting\\MonitoringAgent") and not (((ProcessName contains "Microsoft.Identity.Health.Adfs.DiagnosticsAgent.exe" or ProcessName contains "Microsoft.Identity.Health.Adfs.InsightsService.exe" or ProcessName contains "Microsoft.Identity.Health.Adfs.MonitoringAgent.Startup.exe" or ProcessName contains "Microsoft.Identity.Health.Adfs.PshSurrogate.exe" or ProcessName contains "Microsoft.Identity.Health.Common.Clients.ResourceMonitor.exe"))))

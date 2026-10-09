# Title: Azure AD Health Service Agents Registry Keys Access
# ID: 1d2ab8ac-1a01-423b-9c39-001510eae8e8
# Status: test
# Level: medium
# Author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research), MSTIC
# Date: 2021-08-26
# Tags: attack.discovery, attack.t1012
# Description: This detection uses Windows security events to detect suspicious access attempts to the registry key values and sub-keys of Azure AD Health service agents (e.g AD FS).
# Information from AD Health service agents can be used to potentially abuse some of the features provided by those services in the cloud (e.g. Federation).
# This detection requires an access control entry (ACE) on the system access control list (SACL) of the following securable object: HKLM:\SOFTWARE\Microsoft\ADHealthAgent.
# Make sure you set the SACL to propagate to its sub-keys.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Azure AD Health Service Agents Registry Keys Access
def rule(event):
    # Detection Logic:
    # (((EventID="4656" OR EventID="4663") AND ObjectType="Key" AND ObjectName="\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\ADHealthAgent") AND NOT (((ProcessName="*Microsoft.Identity.Health.Adfs.DiagnosticsAgent.exe*" OR ProcessName="*Microsoft.Identity.Health.Adfs.InsightsService.exe*" OR ProcessName="*Microsoft.Identity.Health.Adfs.MonitoringAgent.Startup.exe*" OR ProcessName="*Microsoft.Identity.Health.Adfs.PshSurrogate.exe*" OR ProcessName="*Microsoft.Identity.Health.Common.Clients.ResourceMonitor.exe*"))))
    return True

def title(event):
    return "Azure AD Health Service Agents Registry Keys Access"

